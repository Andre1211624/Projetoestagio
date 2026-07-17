/* =====================================================================
 *  AGENTE DE CAPTURA — Router Asus XT8 (versão libpcap)
 * =====================================================================
 *  Projeto: Framework de Injeção de Ataques IoT — ISEP/SoftCPS
 *
 *  Usa a libpcap (a mesma biblioteca do tcpdump/Wireshark) para
 *  capturar. A libpcap é compilada estaticamente dentro do binário,
 *  por isso o router NÃO precisa de a ter instalada.
 *
 *  Protocolo (igual às outras versões):
 *    PING | START|nome | STOP | GET|nome | LIST
 *
 *  Cross-compilar no Kali (requer libpcap-dev para ARM — ver README):
 *    arm-linux-gnueabihf-gcc -static -o agente_router agente_router_libpcap.c \
 *        -I/caminho/libpcap -L/caminho/libpcap -lpcap -lpthread
 * =====================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <signal.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 9999
#define PCAP_DIR "/tmp"
#define CAPTURE_IFACE "br0"
#define BUFFER_SIZE 4096
#define SNAP_LEN 65535

static pcap_t *pcap_handle = NULL;
static pcap_dumper_t *pcap_dumper = NULL;
static pthread_t capture_thread;
static volatile int capturing = 0;
static char current_pcap[256] = {0};
static char current_pcap_path[512] = {0};

void logmsg(const char *msg) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    printf("[%02d:%02d:%02d] %s\n", t->tm_hour, t->tm_min, t->tm_sec, msg);
    fflush(stdout);
}

void sanitize(const char *in, char *out, size_t max) {
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0' && j < max - 1; i++) {
        char c = in[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_')
            out[j++] = c;
    }
    out[j] = '\0';
    if (j == 0) strcpy(out, "unknown");
}

/* Thread: captura com libpcap e grava no dumper */
void *capture_loop(void *arg) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_handle = pcap_open_live(CAPTURE_IFACE, SNAP_LEN, 1, 100, errbuf);
    if (!pcap_handle) {
        logmsg("ERRO: pcap_open_live falhou");
        capturing = 0;
        return NULL;
    }

    pcap_dumper = pcap_dump_open(pcap_handle, current_pcap_path);
    if (!pcap_dumper) {
        logmsg("ERRO: pcap_dump_open falhou");
        pcap_close(pcap_handle);
        pcap_handle = NULL;
        capturing = 0;
        return NULL;
    }

    /* Loop de captura: pcap_dispatch processa pacotes em blocos */
    while (capturing) {
        pcap_dispatch(pcap_handle, 10, pcap_dump, (u_char *)pcap_dumper);
        pcap_dump_flush(pcap_dumper);
    }

    pcap_dump_close(pcap_dumper);
    pcap_close(pcap_handle);
    pcap_dumper = NULL;
    pcap_handle = NULL;
    logmsg("Thread de captura terminada");
    return NULL;
}

void cmd_start(const char *attack_name, int client) {
    char safe[128], response[512];
    sanitize(attack_name, safe, sizeof(safe));

    if (capturing) {
        capturing = 0;
        pthread_join(capture_thread, NULL);
    }

    long ts = (long)time(NULL);
    snprintf(current_pcap, sizeof(current_pcap), "router_%s_%ld.pcap", safe, ts);
    snprintf(current_pcap_path, sizeof(current_pcap_path), "%s/%s", PCAP_DIR, current_pcap);

    capturing = 1;
    if (pthread_create(&capture_thread, NULL, capture_loop, NULL) != 0) {
        capturing = 0;
        send(client, "ERROR|thread creation failed", 28, 0);
        return;
    }

    snprintf(response, sizeof(response), "OK|Capture started: %s", current_pcap);
    send(client, response, strlen(response), 0);
    char logbuf[600];
    snprintf(logbuf, sizeof(logbuf), "Captura iniciada: %s", current_pcap);
    logmsg(logbuf);
}

void cmd_stop(int client) {
    char response[512];
    if (!capturing) { send(client, "ERROR|No capture running", 24, 0); return; }

    capturing = 0;
    if (pcap_handle) pcap_breakloop(pcap_handle);
    pthread_join(capture_thread, NULL);

    snprintf(response, sizeof(response), "OK|Capture stopped: %s", current_pcap);
    send(client, response, strlen(response), 0);
    char logbuf[400];
    snprintf(logbuf, sizeof(logbuf), "Captura terminada: %s", current_pcap);
    logmsg(logbuf);
}

void cmd_get(const char *attack_name, int client) {
    char safe[128];
    sanitize(attack_name, safe, sizeof(safe));

    DIR *d = opendir(PCAP_DIR);
    if (!d) { send(client, "ERROR|Cannot open dir", 21, 0); return; }
    char prefix[160];
    snprintf(prefix, sizeof(prefix), "router_%s_", safe);
    char latest[256] = {0};
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL)
        if (strncmp(entry->d_name, prefix, strlen(prefix)) == 0)
            if (strcmp(entry->d_name, latest) > 0)
                strncpy(latest, entry->d_name, sizeof(latest) - 1);
    closedir(d);

    if (latest[0] == '\0') {
        char err[256];
        snprintf(err, sizeof(err), "ERROR|No PCAP found for: %s", safe);
        send(client, err, strlen(err), 0);
        return;
    }

    char full_path[600];
    snprintf(full_path, sizeof(full_path), "%s/%s", PCAP_DIR, latest);
    FILE *f = fopen(full_path, "rb");
    if (!f) { send(client, "ERROR|Cannot open PCAP", 22, 0); return; }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char header[512];
    snprintf(header, sizeof(header), "FILE|%s|%ld\n", latest, fsize);
    send(client, header, strlen(header), 0);
    usleep(100000);

    char buf[BUFFER_SIZE];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        size_t sent = 0;
        while (sent < n) {
            ssize_t r = send(client, buf + sent, n - sent, 0);
            if (r <= 0) break;
            sent += r;
        }
    }
    fclose(f);
    char logbuf[700];
    snprintf(logbuf, sizeof(logbuf), "PCAP enviado: %s (%ld bytes)", latest, fsize);
    logmsg(logbuf);
}

void cmd_list(int client) {
    DIR *d = opendir(PCAP_DIR);
    if (!d) { send(client, "OK|No PCAPs available", 21, 0); return; }
    char response[BUFFER_SIZE] = "OK|";
    int found = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL)
        if (strncmp(entry->d_name, "router_", 7) == 0) {
            if (found > 0) strncat(response, ",", sizeof(response) - strlen(response) - 1);
            strncat(response, entry->d_name, sizeof(response) - strlen(response) - 1);
            found++;
        }
    closedir(d);
    if (!found) send(client, "OK|No PCAPs available", 21, 0);
    else send(client, response, strlen(response), 0);
}

void handle_command(char *data, int client) {
    data[strcspn(data, "\r\n")] = '\0';
    char *cmd = data;
    char *arg = strchr(data, '|');
    if (arg) { *arg = '\0'; arg++; }
    char logbuf[600];
    snprintf(logbuf, sizeof(logbuf), "CMD: %s%s%s", cmd, arg ? "|" : "", arg ? arg : "");
    logmsg(logbuf);
    for (char *p = cmd; *p; p++) if (*p >= 'a' && *p <= 'z') *p -= 32;

    if (strcmp(cmd, "PING") == 0) send(client, "OK|Agent alive", 14, 0);
    else if (strcmp(cmd, "START") == 0) cmd_start(arg ? arg : "unknown", client);
    else if (strcmp(cmd, "STOP") == 0) cmd_stop(client);
    else if (strcmp(cmd, "GET") == 0) cmd_get(arg ? arg : "", client);
    else if (strcmp(cmd, "LIST") == 0) cmd_list(client);
    else send(client, "ERROR|Unknown command", 21, 0);
}

int main(void) {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;
    signal(SIGPIPE, SIG_IGN);

    logmsg("=================================================");
    logmsg("AGENTE DE CAPTURA — Asus XT8 (C, libpcap)");

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(server_fd, 5) < 0) { perror("listen"); return 1; }

    char portbuf[64];
    snprintf(portbuf, sizeof(portbuf), "A escutar na porta: %d", PORT);
    logmsg(portbuf);
    char ifbuf[128];
    snprintf(ifbuf, sizeof(ifbuf), "Interface de captura: %s", CAPTURE_IFACE);
    logmsg(ifbuf);
    logmsg("=================================================");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;
        char buffer[BUFFER_SIZE];
        ssize_t n = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (n > 0) { buffer[n] = '\0'; handle_command(buffer, client_fd); }
        close(client_fd);
    }
    close(server_fd);
    return 0;
}
