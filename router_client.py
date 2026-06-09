#!/usr/bin/env python3
"""
=====================================================================
 CLIENTE DO AGENTE — Attack Station (Kali)
=====================================================================
 Projeto: Framework de Injeção de Ataques IoT — ISEP/SoftCPS
 Função:  Módulo que a app Streamlit usa para comunicar com o agente
          de captura que corre no router. Envia comandos START/STOP/GET
          e recebe os ficheiros PCAP de volta.

 Uso na app:
   from router_client import RouterAgent
   agent = RouterAgent("192.168.1.1", 9999)
   agent.start_capture("SYN-Flood")
   ... injeta o ataque ...
   agent.stop_capture()
   agent.get_pcap("SYN-Flood", "/tmp/captura_local.pcap")
=====================================================================
"""

import socket
import time

BUFFER = 4096


class RouterAgent:
    """Cliente para comunicar com o agente de captura no router."""

    def __init__(self, host, port=9999, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout

    def _send_command(self, command):
        """Envia um comando simples e devolve a resposta de texto."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.host, self.port))
                s.sendall(command.encode())
                response = s.recv(BUFFER).decode(errors="ignore")
                return response
        except socket.timeout:
            return "ERROR|Timeout - agente não respondeu"
        except ConnectionRefusedError:
            return "ERROR|Ligação recusada - agente não está a correr?"
        except Exception as e:
            return f"ERROR|{str(e)}"

    def ping(self):
        """Testa se o agente está vivo. Devolve True/False."""
        response = self._send_command("PING")
        return response.startswith("OK")

    def start_capture(self, attack_name):
        """Pede ao router para iniciar a captura."""
        return self._send_command(f"START|{attack_name}")

    def stop_capture(self):
        """Pede ao router para parar a captura."""
        return self._send_command("STOP")

    def list_pcaps(self):
        """Lista os PCAPs disponíveis no router."""
        response = self._send_command("LIST")
        if response.startswith("OK|"):
            pcaps = response[3:]
            return pcaps.split(",") if pcaps != "No PCAPs available" else []
        return []

    def get_pcap(self, attack_name, local_path):
        """
        Descarrega o PCAP do router para um ficheiro local.
        Devolve (sucesso: bool, mensagem: str).
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.host, self.port))
                s.sendall(f"GET|{attack_name}".encode())

                # Lê o cabeçalho: FILE|nome|tamanho\n
                header = b""
                while b"\n" not in header:
                    chunk = s.recv(1)
                    if not chunk:
                        break
                    header += chunk

                header_str = header.decode(errors="ignore").strip()

                if header_str.startswith("ERROR"):
                    return (False, header_str)

                if not header_str.startswith("FILE|"):
                    return (False, f"Resposta inesperada: {header_str}")

                _, filename, filesize = header_str.split("|")
                filesize = int(filesize)

                # Recebe o ficheiro
                received = 0
                with open(local_path, "wb") as f:
                    while received < filesize:
                        chunk = s.recv(min(BUFFER, filesize - received))
                        if not chunk:
                            break
                        f.write(chunk)
                        received += len(chunk)

                if received == filesize:
                    return (True, f"PCAP descarregado: {filename} ({filesize} bytes)")
                else:
                    return (False, f"Transferência incompleta: {received}/{filesize} bytes")

        except Exception as e:
            return (False, f"Erro ao descarregar: {str(e)}")


# --- TESTE RÁPIDO (corre este ficheiro diretamente para testar) ---
if __name__ == "__main__":
    print("Teste do cliente do agente")
    print("=" * 40)

    agent = RouterAgent("127.0.0.1", 9999)  # localhost para teste no Kali

    print("1. PING ao agente...")
    if agent.ping():
        print("   ✅ Agente está vivo!")
    else:
        print("   ❌ Agente não responde. Está a correr o agente_router.py?")
        exit(1)

    print("2. Iniciar captura...")
    print("   " + agent.start_capture("TESTE"))

    print("3. A capturar durante 5 segundos...")
    time.sleep(5)

    print("4. Parar captura...")
    print("   " + agent.stop_capture())

    print("5. Listar PCAPs no router...")
    print("   " + str(agent.list_pcaps()))

    print("6. Descarregar PCAP...")
    ok, msg = agent.get_pcap("TESTE", "/tmp/teste_descarregado.pcap")
    print(f"   {'✅' if ok else '❌'} {msg}")

    print("=" * 40)
    print("Teste concluído!")
