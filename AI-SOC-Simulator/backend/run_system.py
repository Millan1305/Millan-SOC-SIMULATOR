import subprocess
import time
import sys


print("🚀 STARTING AI SOC SYSTEM...")

# =========================
# START BACKEND API (app.py)
# =========================
print("🔹 Starting API Server (app.py)...")
api_process = subprocess.Popen([sys.executable, "app.py"])

time.sleep(2)

# =========================
# START REALTIME ENGINE
# =========================
print("🔹 Starting Realtime Engine...")
realtime_process = subprocess.Popen([sys.executable, "realtime_engine.py"])

time.sleep(2)

print("\n✅ SOC SYSTEM FULLY RUNNING!")
print("🌐 API: http://localhost:5000")
print("📡 Realtime: http://localhost:6000")
print("🛡 Dashboard: Open frontend/index.html")

# =========================
# KEEP SCRIPT ALIVE
# =========================
try:
    api_process.wait()
    realtime_process.wait()
except KeyboardInterrupt:
    print("\n🛑 Shutting down SOC system...")
    api_process.terminate()
    realtime_process.terminate()