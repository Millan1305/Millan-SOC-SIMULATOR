# AI-Powered SOC Security Automation Dashboard 🛡️

An enterprise-grade, high-tech real-time Security Operations Center (SOC) simulator. This platform ingests Windows Security kernel events and raw network log structures, analyzes threat vectors using an AI Engine, and executes automated mitigation response containment actions (like IP blocking).

## 🚀 Features
- **Real-Time Log Ingestion & Parsing:** Subprocess multi-threading architecture parsing system logs.
- **AI Threat Scoring Engine:** Micro-scaled anomaly vector analyzer scoring inputs dynamically (0-100% scale).
- **Automated Incident Response Engine:** Immediate isolation counters blocking malicious attacker nodes.
- **Hitech Volatile Streaming Terminal:** Real-time fluid dark-mode UI with operational gauge counters and live streaming matrices feed.

🚀 Steps to Run the Project (Live Pipeline)
Follow these exact steps in order to boot up the complete automated security simulation framework:

Step 1: Start the Flask Gateway Server
Open a normal terminal/PowerShell window, navigate to the backend folder, and launch the core API router:

PowerShell
cd backend
python app.py
🎛️ Status Check: Leave this window running. The server will boot up locally at http://localhost:5000.

Step 2: Open PowerShell as Administrator
To capture live Windows Security event logs from the OS kernel, the log collector script requires administrative privileges:

Click the Windows Start Menu, search for PowerShell.

Right-click it and select "Run as Administrator".

Step 3: Launch the Windows Live Log Collector Daemon
Inside the newly opened Administrator PowerShell window, navigate to your project's backend directory path and execute the streaming daemon:

PowerShell
cd \path\To\Your\AI-SOC-Simulator\backend
python system_log_collector.py
📡 Status Check: This terminal will enter an infinite loop, capturing local machine security traces (📥 [CAPTURED WIN_EVENT]) and continuously pushing them (🚀 [TRANSMITTED]) directly into the active Flask server.
