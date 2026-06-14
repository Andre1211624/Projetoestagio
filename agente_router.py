#!/usr/bin/env python3
"""
=====================================================================
 AGENTE DE CAPTURA — Router Hitron (RDK-B)
=====================================================================
 Projeto: Framework de Injeção de Ataques IoT — ISEP/SoftCPS
 Função:  Agente leve que corre no router e orquestra a captura de
          tráfego (tcpdump) mediante comandos enviados pela Attack
          Station. Captura TODO o tráfego (cabo + Wi-Fi) num único
          ponto de observação.

 Filosofia "leve": o agente NÃO processa pacotes em Python. Apenas
 recebe comandos e lança/termina o tcpdump (processo C otimizado).
 O Python fica idle entre capturas — consumo de recursos mínimo.

 Protocolo (texto simples sobre TCP):
   PING                -> responde "OK"
   START|nome_ataque   -> inicia tcpdump, grava PCAP
   STOP                -> termina o tcpdump
   GET|nome_ataque     -> envia o ficheiro PCAP de volta
   LIST                -> lista PCAPs disponíveis

 Uso no router:
   python3 agente_router.py

 Para testar no Kali (simulando o router), corre este mesmo script
 numa janela de terminal; usa a interface 'lo' ou 'eth0' para testar.
=====================================================================
"""

import socket
import subprocess
import os
import signal
import time

# --- CONFIGURAÇÃO ---
HOST = "0.0.0.0"          # escuta em todas as interfaces
PORT = 9999               # porta do agente (escolhe uma livre)
PCAP_DIR = "/tmp"         # onde guardar os PCAPs (no router pode ser USB: /mnt/usb)
CAPTURE_IFACE = "any"     # interface que vê todo o tráfego LAN+WiFi no router
                          # (no Kali para testar, muda para "eth0" ou "any")
BUFFER = 4096

# Estado global: processo de captura ativo
capture_process = None
current_pcap = None


def log(msg):
    """Log simples com timestamp."""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def start_capture(attack_name):
    """Inicia o tcpdump numa interface, gravando para ficheiro PCAP."""
    global capture_process, current_pcap

    # Se já houver uma captura a decorrer, para primeiro
    if capture_process is not None:
        stop_capture()

    timestamp = int(time.time())
    pcap_name = f"router_{attack_name}_{timestamp}.pcap"
    current_pcap = os.path.join(PCAP_DIR, pcap_name)

    # Lança o tcpdump (o trabalho pesado é dele, não do Python)
    # -i interface | -w ficheiro | -U (escrita imediata) | -s 0 (pacote completo)
    cmd = ["tcpdump", "-i", CAPTURE_IFACE, "-w", current_pcap, "-U", "-s", "0"]

    try:
        capture_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log(f"Captura iniciada: {pcap_name} (PID {capture_process.pid})")
        return f"OK|Capture started: {pcap_name}"
    except FileNotFoundError:
        return "ERROR|tcpdump not found on this system"
    except Exception as e:
        return f"ERROR|{str(e)}"


def stop_capture():
    """Termina o processo de captura de forma limpa."""
    global capture_process, current_pcap

    if capture_process is None:
        return "ERROR|No capture running"

    try:
        # SIGTERM permite ao tcpdump fechar o ficheiro PCAP corretamente
        capture_process.send_signal(signal.SIGTERM)
        capture_process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        capture_process.kill()
    except Exception as e:
        log(f"Erro ao parar captura: {e}")

    finished_pcap = current_pcap
    pid = capture_process.pid
    capture_process = None
    log(f"Captura terminada (PID {pid}): {os.path.basename(finished_pcap)}")
    return f"OK|Capture stopped: {os.path.basename(finished_pcap)}"


def send_pcap(conn, attack_name):
    """Envia o ficheiro PCAP mais recente desse ataque de volta para a app."""
    # Procura o PCAP mais recente que corresponda ao nome do ataque
    matching = [
        f for f in os.listdir(PCAP_DIR)
        if f.startswith(f"router_{attack_name}_") and f.endswith(".pcap")
    ]
    if not matching:
        conn.sendall(b"ERROR|No PCAP found for that attack")
        return

    matching.sort()
    pcap_path = os.path.join(PCAP_DIR, matching[-1])
    file_size = os.path.getsize(pcap_path)

    # Envia primeiro um cabeçalho com o tamanho, depois o ficheiro
    header = f"FILE|{os.path.basename(pcap_path)}|{file_size}\n"
    conn.sendall(header.encode())
    time.sleep(0.1)  # pequena pausa para a app processar o cabeçalho

    with open(pcap_path, "rb") as f:
        while True:
            chunk = f.read(BUFFER)
            if not chunk:
                break
            conn.sendall(chunk)

    log(f"PCAP enviado: {os.path.basename(pcap_path)} ({file_size} bytes)")


def list_pcaps():
    """Lista os PCAPs disponíveis no diretório."""
    pcaps = [f for f in os.listdir(PCAP_DIR) if f.endswith(".pcap")]
    if not pcaps:
        return "OK|No PCAPs available"
    return "OK|" + ",".join(sorted(pcaps))


def handle_command(conn, data):
    """Processa um comando recebido."""
    parts = data.strip().split("|")
    cmd = parts[0].upper()

    if cmd == "PING":
        conn.sendall(b"OK|Agent alive")

    elif cmd == "START":
        attack_name = parts[1] if len(parts) > 1 else "unknown"
        # Sanitiza o nome (evita caracteres problemáticos)
        attack_name = "".join(c for c in attack_name if c.isalnum() or c in "-_")
        response = start_capture(attack_name)
        conn.sendall(response.encode())

    elif cmd == "STOP":
        response = stop_capture()
        conn.sendall(response.encode())

    elif cmd == "GET":
        attack_name = parts[1] if len(parts) > 1 else ""
        attack_name = "".join(c for c in attack_name if c.isalnum() or c in "-_")
        send_pcap(conn, attack_name)

    elif cmd == "LIST":
        conn.sendall(list_pcaps().encode())

    else:
        conn.sendall(b"ERROR|Unknown command")


def main():
    log("=" * 50)
    log("AGENTE DE CAPTURA — Router Hitron")
    log(f"A escutar em {HOST}:{PORT}")
    log(f"Interface de captura: {CAPTURE_IFACE}")
    log(f"Diretório PCAP: {PCAP_DIR}")
    log("=" * 50)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)

    try:
        while True:
            conn, addr = server.accept()
            log(f"Ligação de {addr[0]}:{addr[1]}")
            try:
                data = conn.recv(BUFFER).decode(errors="ignore")
                if data:
                    log(f"Comando recebido: {data.strip()}")
                    handle_command(conn, data)
            except Exception as e:
                log(f"Erro ao processar: {e}")
            finally:
                conn.close()
    except KeyboardInterrupt:
        log("Agente terminado pelo utilizador.")
        if capture_process:
            stop_capture()
    finally:
        server.close()


if __name__ == "__main__":
    main()
