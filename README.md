# 🛡️ SOC Automation Tool (SOAR)

### 📖 Project Overview
A Python-based Security Orchestration, Automation, and Response (SOAR) platform designed to assist Level 1 SOC analysts. This tool automates the detection, enrichment, and response lifecycle for security incidents.

### 🚀 Key Features
* **Log Ingestion:** Parses simulated server logs (SSH, HTTP, TCP) to detect brute-force patterns.
* **Threat Intelligence:** Integrated **VirusTotal API** to scan suspicious IPs in real-time.
* **Automated Response:** Simulates firewall blocking actions for confirmed malicious actors.
* **Reporting:** Generates CSV compliance reports for audit trails.

### 🛠️ Tech Stack
* **Python 3.12**
* **Streamlit** (Dashboard UI)
* **Pandas** (Data Analysis)
* **Requests** (API Handling)

### ⚙️ How to Run
1.  Clone the repository:
    ```bash
    git clone  https://github.com/Adnan-M-Faizal/SOC-Automation-Tool.git
    ```
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Run the application:
    ```bash
    streamlit run dashboard.py
    ```

---
*Developed by Adnan Faizal as part of the TCS iON Industry Internship.*
