import streamlit as st
import pandas as pd
import random
import requests
from faker import Faker
import time
from datetime import datetime

# --- CONFIGURATION ---
st.set_page_config(page_title="TCS iON SOAR Platform", layout="wide")
st.title("🛡️ SOAR Platform: Detect, Enrich, Respond")
st.markdown("### Security Orchestration, Automation, and Response Dashboard")

# Sidebar
st.sidebar.header("⚙️ Configuration")
api_key = st.sidebar.text_input("VirusTotal API Key", type="password")
auto_block = st.sidebar.checkbox("Enable Automated Blocking", value=True)
st.sidebar.info("If enabled, 'Malicious' IPs will be automatically added to the Firewall Blocklist.")

# --- BACKEND LOGIC ---
fake = Faker()

def generate_logs(num=20):
    data = []
    # Mix of safe and suspicious IPs
    ips = [fake.ipv4() for _ in range(15)] + ["192.168.1.5", "111.222.33.44", "8.8.8.8"]
    
    for _ in range(num):
        entry = {
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Source_IP": random.choice(ips),
            "Event": random.choice(["Brute Force", "SSH Login", "Malware Download", "Port Scan"]),
            "Status": random.choice(["Failed", "Success"]),
            "Protocol": random.choice(["TCP", "UDP", "HTTP"])
        }
        data.append(entry)
    return pd.DataFrame(data)

def scan_ip(ip, key):
    # SIMULATION MODE (Fast)
    if not key:
        time.sleep(0.1)
        # Randomly decide if it's bad for demo purposes
        return random.choice([0, 0, 0, 5, 88]) 
    
    # REAL MODE (Slow)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()['data']['attributes']['last_analysis_stats']['malicious']
    except:
        pass
    return -1

# --- UI LAYOUT ---
tab1, tab2, tab3 = st.tabs(["1. Monitor & Detect", "2. Threat Intel & Response", "3. Reports & Audits"])

# --- TAB 1: MONITORING ---
with tab1:
    st.subheader("Live Log Ingestion")
    if st.button("🔴 Ingest System Logs", key="ingest"):
        with st.spinner("Parsing logs from SIEM..."):
            df = generate_logs(50)
            # Filter logic: Only care about "Failed" or "Brute Force"
            suspicious = df[(df['Event'] == "Brute Force") | (df['Status'] == "Failed")]
            st.session_state['alerts'] = suspicious
            st.success(f"Ingested {len(df)} logs. Detected {len(suspicious)} suspicious events.")
    
    if 'alerts' in st.session_state:
        st.dataframe(st.session_state['alerts'], use_container_width=True)

# --- TAB 2: ENRICHMENT & RESPONSE ---
with tab2:
    st.subheader("Automated Threat Response")
    if 'alerts' in st.session_state:
        if st.button("⚡ Run SOAR Playbook"):
            results = []
            blocklist = []
            
            progress = st.progress(0)
            alerts = st.session_state['alerts'].drop_duplicates(subset=['Source_IP'])
            total = len(alerts)
            
            for idx, row in alerts.iterrows():
                ip = row['Source_IP']
                
                # 1. Enrichment (Milestone 2)
                score = scan_ip(ip, api_key)
                
                # 2. Decision Logic
                verdict = "CLEAN"
                if score > 0: verdict = "MALICIOUS"
                
                # 3. Response (Milestone 2 - Part B)
                action = "Monitor"
                if verdict == "MALICIOUS" and auto_block:
                    action = "BLOCKED on Firewall"
                    blocklist.append({"IP": ip, "Reason": "VirusTotal Flagged", "Time": datetime.now()})
                
                results.append({
                    "IP": ip,
                    "Malicious_Score": score,
                    "Verdict": verdict,
                    "Automated_Action": action
                })
                time.sleep(0.1)
                progress.progress((len(results)) / total)
            
            st.session_state['soar_results'] = pd.DataFrame(results)
            st.session_state['blocklist'] = pd.DataFrame(blocklist)
            st.success("Playbook execution complete.")

    if 'soar_results' in st.session_state:
        # Show the fancy results table
        def color_row(row):
            return ['background-color: #ffcccc' if row['Verdict'] == "MALICIOUS" else '' for _ in row]
        
        st.table(st.session_state['soar_results'].style.apply(color_row, axis=1))

# --- TAB 3: REPORTING ---
with tab3:
    st.header("🛡️ Firewall Blocklist (Active)")
    if 'blocklist' in st.session_state and not st.session_state['blocklist'].empty:
        st.warning(f"Active Blocks: {len(st.session_state['blocklist'])} IPs")
        st.dataframe(st.session_state['blocklist'], use_container_width=True)
        
        # CSV Download (Requirement #7)
        csv = st.session_state['soar_results'].to_csv(index=False).encode('utf-8')
        st.download_button(
            "📄 Download Compliance Report (CSV)",
            csv,
            "soc_incident_report.csv",
            "text/csv",
            key='download-csv'
        )
    else:
        st.info("No IPs blocked yet. Run the SOAR Playbook in Tab 2.")