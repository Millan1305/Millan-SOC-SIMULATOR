# 🛡️ AI-Powered SOC Security Automation Dashboard

An enterprise-grade Security Operations Center (SOC) simulation platform designed to demonstrate real-time threat monitoring, AI-driven security analytics, and automated incident response workflows.

The system continuously ingests Windows Security Event Logs, analyzes activity using an AI-based threat scoring engine, and performs automated mitigation actions to simulate modern SOC operations.

---

## 🚀 Features

### 📥 Real-Time Log Collection

* Live ingestion of Windows Security Event Logs
* Multi-threaded log collection architecture
* Continuous event streaming pipeline

### 🤖 AI Threat Analysis Engine

* Dynamic threat scoring (0–100%)
* Behavioral anomaly detection
* Risk-based event prioritization

### ⚡ Automated Incident Response

* Automatic malicious IP identification
* Simulated containment and response actions
* Real-time mitigation workflow execution

### 📊 Interactive SOC Dashboard

* Live event monitoring
* Threat severity visualization
* Security metrics and analytics
* Dark-mode operational interface
* Real-time streaming activity feed

---

## 🏗️ System Architecture

```text
Windows Security Logs
          │
          ▼
System Log Collector
          │
          ▼
Flask API Gateway
          │
          ▼
AI Threat Analysis Engine
          │
          ▼
Automated Response Engine
          │
          ▼
SOC Security Dashboard
```

---

## 🛠️ Tech Stack

### Backend

* Python
* Flask
* Flask-SocketIO
* Threading
* Windows Event Log API

### Frontend

* HTML5
* CSS3
* JavaScript
* Socket.IO

### Security Components

* Log Collection Engine
* Threat Scoring Engine
* Alert Management System
* Incident Response Module

---

## 📂 Project Structure

```text
AI-SOC-Simulator/
│
├── backend/
│   ├── app.py
│   ├── realtime_engine.py
│   ├── system_log_collector.py
│   ├── alert_system.py
│   └── requirements.txt
│
├── frontend/
│   ├── index.html
│   ├── script.js
│   ├── style.css
│
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

* Python 3.10+
* Windows Operating System
* Administrator Privileges
* Modern Web Browser

---

## ▶️ Running the Project

### Step 1: Start the Flask Backend

Open a terminal and run:

```bash
cd backend
python app.py
```

Expected output:

```text
Server running on:
http://localhost:5000
```

Keep this terminal running.

---

### Step 2: Open PowerShell as Administrator

To access Windows Security Event Logs:

1. Open Start Menu
2. Search for PowerShell
3. Right-click PowerShell
4. Select "Run as Administrator"

---

### Step 3: Launch the Log Collector

In the Administrator PowerShell window:

```powershell
cd path\to\AI-SOC-Simulator\backend
python system_log_collector.py
```

Expected output:

```text
[CAPTURED] Windows Security Event
[PARSED] Event Processed
[TRANSMITTED] Sent to Server
[ANALYZED] Threat Score Generated
```

The collector continuously streams security telemetry to the Flask backend.

---

### Step 4: Open the Dashboard

Launch the frontend and access:

```text
http://localhost:3000
```

The dashboard provides:

* Live Security Events
* Threat Score Monitoring
* Incident Severity Tracking
* Security Metrics
* Automated Response Visualization
* Blocked IP Activity

---

## 🔄 Workflow

```text
Security Event Generated
          │
          ▼
Event Captured
          │
          ▼
Threat Analysis
          │
          ▼
Risk Scoring
          │
          ▼
Alert Generation
          │
          ▼
Automated Response
          │
          ▼
Dashboard Visualization
```

---

---

## 🎯 Learning Objectives

This project demonstrates:

* Security Operations Center (SOC) workflows
* Security Information and Event Management (SIEM) concepts
* Real-time log processing
* Threat detection and analysis
* Incident response automation
* Security dashboard development
* Flask and Socket.IO integration

---

## 🔮 Future Enhancements

* Machine Learning-based anomaly detection
* MITRE ATT&CK mapping
* Threat intelligence integration
* Role-Based Access Control (RBAC)
* Multi-endpoint monitoring
* Cloud log ingestion support
* Advanced reporting and analytics

---

## 📄 License

This project is intended for educational, research, and portfolio purposes.

---

## 👨‍💻 Author

**Millan Kumar Behera**

Cybersecurity Enthusiast | SOC Analyst | Security Automation Developer

If you found this project useful, consider giving it a ⭐ on GitHub.
