from flask import Flask
from flask_socketio import SocketIO
from datetime import datetime
import random
import time

from alert_system import AlertSystem

# =========================
# FLASK + SOCKET INIT
# =========================
app = Flask(__name__)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

alert_system = AlertSystem()

# =========================
# ATTACK TYPES
# =========================
ATTACK_TYPES = [
    "BRUTE_FORCE",
    "PORT_SCAN",
    "MALWARE",
    "RANSOMWARE",
    "DATA_EXFILTRATION",
    "POWERSHELL_ABUSE",
    "PRIVILEGE_ESCALATION",
    "BLACKLISTED_IP"
]

SEVERITY_MAP = {
    "BRUTE_FORCE": "HIGH",
    "PORT_SCAN": "MEDIUM",
    "MALWARE": "CRITICAL",
    "RANSOMWARE": "CRITICAL",
    "DATA_EXFILTRATION": "CRITICAL",
    "POWERSHELL_ABUSE": "HIGH",
    "PRIVILEGE_ESCALATION": "HIGH",
    "BLACKLISTED_IP": "CRITICAL"
}

# =========================
# GENERATE EVENT
# =========================
def generate_event():
    attack = random.choice(ATTACK_TYPES)

    return {
        "event_id": f"EVT-{int(time.time()*1000)}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attack_type": attack,
        "severity": SEVERITY_MAP.get(attack, "LOW"),
        "threat_score": random.randint(10, 100),
        "source_ip": f"192.168.1.{random.randint(2, 254)}"
    }

# =========================
# PROCESS EVENT
# =========================
def process_event(event):

    socketio.emit("new_log", event)

    if event["severity"] == "CRITICAL":
        alert = alert_system.create_alert(
            attack_type=event["attack_type"],
            severity=event["severity"],
            score=event["threat_score"],
            target_ip=event["source_ip"]
        )

        socketio.emit("critical_alert", alert)

# =========================
# STREAM LOOP
# =========================
def stream_logs():
    print("🚀 SOC Realtime Engine Running...")

    while True:
        try:
            event = generate_event()
            process_event(event)
            time.sleep(2)

        except Exception as e:
            print("Error:", e)

# =========================
# BACKGROUND START
# =========================
def start_engine():
    socketio.start_background_task(stream_logs)

# =========================
# SOCKET EVENTS
# =========================
@socketio.on("connect")
def connect():
    print("🟢 Client Connected")

@socketio.on("disconnect")
def disconnect():
    print("🔴 Client Disconnected")

# =========================
# MAIN
# =========================
if __name__ == "__main__":

    start_engine()

    # ✅ FIXED PORT (IMPORTANT)
    socketio.run(app, host="0.0.0.0", port=5001, debug=True)