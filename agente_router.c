/* =====================================================================
 *  AGENTE DE CAPTURA — Router Asus XT8 (versão em C)
 * =====================================================================
 *  Projeto: Framework de Injeção de Ataques IoT — ISEP/SoftCPS
 *
 *  Servidor TCP leve que controla o tcpdump no router. Recebe comandos
 *  da Attack Station e devolve os ficheiros PCAP capturados.
 *
 *  Protocolo (texto simples, uma ligação TCP por comando):
 *    PING              -> "OK|Agent alive"
 *    START|nome_ataque -> inicia tcpdump, responde "OK|..."
 *    STOP              -> para o tcpdump, responde "OK|..."
 *    GET|nome_ataque   -> envia "FILE|nome|tamanho\n" + bytes do PCAP
 *    LIST              -> "OK|ficheiro1,ficheiro2,..."
 *
 *  Compilar no router:
 *    gcc -o agente_router agente_router.c
 *
 *  Correr:
 *    ./agente_router
 *
 *  Em background (sobrevive ao fecho do SSH):
 *    ./agente_router &
 * =====================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* --- CONFIGURAÇÃO --- */
#define PORT 9999
#define PCAP_DIR "/tmp"
#define CAPTURE_IFACE "br0"   /* interface que vê todo o tráfego no router */
#define BUFFER_SIZE 4096

/* Estado da captura ativa */
static pid_t tcpdump_pid = -1;
static char current_pcap[256] = {0};

/* --- LOG com timestamp --- */
void logmsg(const char *msg) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    printf("[%02d:%02d:%02d] %s\n", t->tm_hour, t->tm_min, t->tm_sec, msg);
    fflush(stdout);
}

/* --- Sanitiza nome do ataque (só alfanumérico, traço e underscore) --- */
void sanitize(const char *in, char *out, size_t max) {
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0' && j < max - 1; i++) {
        char c = in[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_') {
            out[j++] = c;
        }
    }
    out[j] = '\0';
    if (j == 0) {
        strcpy(out, "unknown");
    }
}

/* --- INICIAR CAPTURA --- */
void cmd_start(const char *attack_name, int client) {
    char safe[128];
    char response[512];
    sanitize(attack_name, safe, sizeof(safe));

    /* Se já há captura, para primeiro */
    if (tcpdump_pid > 0) {
        kill(tcpdump_pid, SIGTERM);
        waitpid(tcpdump_pid, NULL, 0);
        tcpdump_pid = -1;
    }

    /* Constrói o nome do ficheiro PCAP */
    char pcap_path[512];
    long ts = (long)time(NULL);
    snprintf(current_pcap, sizeof(current_pcap), "router_%s_%ld.pcap", safe, ts);
    snprintf(pcap_path, sizeof(pcap_path), "%s/%s", PCAP_DIR, current_pcap);

    /* Lança o tcpdump como processo filho */
    pid_t pid = fork();
    if (pid == 0) {
        /* Processo filho: executa tcpdump */
        int devnull = open("/dev/null", 1); /* O_WRONLY */
        if (devnull >= 0) {
            dup2(devnull, 1);
            dup2(devnull, 2);
        }
        execlp("tcpdump", "tcpdump", "-i", CAPTURE_IFACE,
               "-w", pcap_path, "-U", "-s", "0", (char *)NULL);
        /* Se chegou aqui, o exec falhou */
        _exit(127);
    } else if (pid > 0) {
        tcpdump_pid = pid;
        snprintf(response, sizeof(response), "OK|Capture started: %s", current_pcap);
        send(client, response, strlen(response), 0);

        char logbuf[600];
        snprintf(logbuf, sizeof(logbuf), "Captura iniciada: %s (PID %d)", current_pcap, pid);
        logmsg(logbuf);
    } else {
        send(client, "ERROR|fork failed", 17, 0);
    }
}

/* --- PARAR CAPTURA --- */
void cmd_stop(int client) {
    char response[512];

    if (tcpdump_pid <= 0) {
        send(client, "ERROR|No capture running", 24, 0);
        return;
    }

    /* SIGTERM permite ao tcpdump fechar o ficheiro PCAP corretamente */
    kill(tcpdump_pid, SIGTERM);
    waitpid(tcpdump_pid, NULL, 0);

    char logbuf[400];
    snprintf(logbuf, sizeof(logbuf), "Captura terminada (PID %d): %s", tcpdump_pid, current_pcap);
    logmsg(logbuf);

    snprintf(response, sizeof(response), "OK|Capture stopped: %s", current_pcap);
    send(client, response, strlen(response), 0);

    tcpdump_pid = -1;
}

/* --- ENVIAR PCAP --- */
void cmd_get(const char *attack_name, int client) {
    char safe[128];
    sanitize(attack_name, safe, sizeof(safe));

    /* Procura o PCAP mais recente que comece por router_<nome>_ */
    DIR *d = opendir(PCAP_DIR);
    if (!d) {
        send(client, "ERROR|Cannot open PCAP dir", 26, 0);
        return;
    }

    char prefix[160];
    snprintf(prefix, sizeof(prefix), "router_%s_", safe);

    char latest[256] = {0};
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (strncmp(entry->d_name, prefix, strlen(prefix)) == 0) {
            /* Compara para ficar com o mais recente (nome tem timestamp) */
            if (strcmp(entry->d_name, latest) > 0) {
                strncpy(latest, entry->d_name, sizeof(latest) - 1);
            }
        }
    }
    closedir(d);

    if (latest[0] == '\0') {
        char err[256];
        snprintf(err, sizeof(err), "ERROR|No PCAP found for: %s", safe);
        send(client, err, strlen(err), 0);
        return;
    }

    /* Abre o ficheiro e envia cabeçalho + conteúdo */
    char full_path[600];
    snprintf(full_path, sizeof(full_path), "%s/%s", PCAP_DIR, latest);

    FILE *f = fopen(full_path, "rb");
    if (!f) {
        send(client, "ERROR|Cannot open PCAP file", 27, 0);
        return;
    }

    /* Tamanho do ficheiro */
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    /* Envia cabeçalho: FILE|nome|tamanho\n */
    char header[512];
    snprintf(header, sizeof(header), "FILE|%s|%ld\n", latest, fsize);
    send(client, header, strlen(header), 0);
    usleep(100000); /* 0.1s para o cliente processar o cabeçalho */

    /* Envia o conteúdo do ficheiro */
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

/* --- LISTAR PCAPs --- */
void cmd_list(int client) {
    DIR *d = opendir(PCAP_DIR);
    if (!d) {
        send(client, "OK|No PCAPs available", 21, 0);
        return;
    }

    char response[BUFFER_SIZE] = "OK|";
    int found = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (strncmp(entry->d_name, "router_", 7) == 0) {
            if (found > 0) strncat(response, ",", sizeof(response) - strlen(response) - 1);
            strncat(response, entry->d_name, sizeof(response) - strlen(response) - 1);
            found++;
        }
    }
    closedir(d);

    if (!found) {
        send(client, "OK|No PCAPs available", 21, 0);
    } else {
        send(client, response, strlen(response), 0);
    }
}

/* --- PROCESSAR UM COMANDO --- */
void handle_command(char *data, int client) {
    /* Remove \r e \n do fim */
    data[strcspn(data, "\r\n")] = '\0';

    /* Separa comando e argumento por | */
    char *cmd = data;
    char *arg = strchr(data, '|');
    if (arg) {
        *arg = '\0';
        arg++;
    }

    char logbuf[600];
    snprintf(logbuf, sizeof(logbuf), "CMD: %s%s%s", cmd, arg ? "|" : "", arg ? arg : "");
    logmsg(logbuf);

    /* Converte comando para maiúsculas */
    for (char *p = cmd; *p; p++) {
        if (*p >= 'a' && *p <= 'z') *p -= 32;
    }

    if (strcmp(cmd, "PING") == 0) {
        send(client, "OK|Agent alive", 14, 0);
    } else if (strcmp(cmd, "START") == 0) {
        cmd_start(arg ? arg : "unknown", client);
    } else if (strcmp(cmd, "STOP") == 0) {
        cmd_stop(client);
    } else if (strcmp(cmd, "GET") == 0) {
        cmd_get(arg ? arg : "", client);
    } else if (strcmp(cmd, "LIST") == 0) {
        cmd_list(client);
    } else {
        send(client, "ERROR|Unknown command", 21, 0);
    }
}

/* --- MAIN: servidor TCP --- */
int main(void) {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;

    /* Ignora SIGCHLD para evitar processos zombie do tcpdump */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    logmsg("=================================================");
    logmsg("AGENTE DE CAPTURA — Asus XT8 (C)");

    /* Cria o socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    /* Permite reutilizar o porto imediatamente após reinício */
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen");
        return 1;
    }

    char portbuf[64];
    snprintf(portbuf, sizeof(portbuf), "A escutar na porta: %d", PORT);
    logmsg(portbuf);
    char ifbuf[128];
    snprintf(ifbuf, sizeof(ifbuf), "Interface de captura: %s", CAPTURE_IFACE);
    logmsg(ifbuf);
    logmsg("=================================================");

    /* Loop principal: aceita e processa uma ligação de cada vez */
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            continue;
        }

        char buffer[BUFFER_SIZE];
        ssize_t n = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            handle_command(buffer, client_fd);
        }

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
