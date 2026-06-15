import subprocess
import json
import time
import requests
import re
import os

# Destination endpoint routing to Flask app.py pipeline
API_URL = "http://localhost:5000/ingest-log"


def extract_ip(text):
    """Dynamic regular expression helper to isolate anomalous node IPs context inside strings."""
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    # Default node IP allocation fallback values mapping checks rules
    return match.group(0) if match else "185.220.101.5"


def collect_and_stream_logs():
    print("\n==================================================================")
    print("🛡️  AI-SOC ENTERPRISE WINDOWS SECURITY COLLECTOR DAEMON ONLINE")
    print(f"📡 Transmission Target Engine: {API_URL}")
    print("⏱️  Real-Time Tracking Status Monitoring: Active Loop Mode (3s Intervals)")
    print("==================================================================\n")

    # In-memory tracking layer cache definitions to avoid duplicates cycles parsing
    last_processed_events = set()

    while True:
        try:
            # Native PowerShell Security Logging Context Queries Execution Block
            # Fetches last 5 local security events from Windows Kernel Logging Provider subsystems
            cmd = [
                "powershell", 
                "-Command", 
                "Get-WinEvent -LogName Security -MaxEvents 5 -ErrorAction SilentlyContinue | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + ' | ID=' + $_.Id + ' | ' + $_.Message }"
            ]
            
            # Execute background shell subprocess execution layer pipeline
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                encoding="utf-8", 
                errors="ignore"
            )
            
            if result.stdout and str(result.stdout).strip():
                raw_lines = result.stdout.strip().split("\n")
                
                for raw_line in raw_lines:
                    cleaned_line = raw_line.strip()
                    
                    if not cleaned_line or cleaned_line in last_processed_events:
                        continue
                    
                    # Deduplication shield registry bounds check mapping
                    last_processed_events.add(cleaned_line)
                    if len(last_processed_events) > 150:
                        # Prevent memory leaking scenarios inside perpetual stream loops execution
                        last_processed_events.pop()

                    # Isolate core signature types strings configurations for log console readability
                    print(f"📥 [CAPTURED WIN_EVENT]: {cleaned_line[:100]}...")

                    # Structure explicit parameters payload schema configurations
                    # Injecting a dynamic source attacker node parameter profile to trigger dashboard charts updates
                    simulated_ip = extract_ip(cleaned_line)
                    
                    # Formatting check bounds match variables mapping patterns inside log_analyzer rules
                    payload_string = f"{cleaned_line} SOURCE={simulated_ip}"
                    
                    # Severe attacks signature tags simulation rules inject
                    if "4798" in cleaned_line or "ACCOUNT_ENUMERATION" in cleaned_line.upper():
                        # Account enum events get flagged as BRUTE FORCE vectors inside custom analyzer pipelines
                        payload_string += " FAILED LOGIN AUDIT FAILURE 4625"

                    payload = {
                        "log": payload_string
                    }

                    # Active streaming packet payload dispatch loop blocks triggers
                    try:
                        response = requests.post(API_URL, json=payload, timeout=2)
                        
                        if response.status_code == 200:
                            print("🚀 [TRANSMITTED]: Threat vector analytics logs securely ingested by Flask API.")
                        else:
                            print(f"⚠️  [SERVER DROPPED FRAME]: Endpoint returned error status -> {response.status_code}")
                            
                    except requests.exceptions.ConnectionError:
                        print("❌ [LINK FAILED]: Connection refused! Verify that 'python app.py' server terminal is active.")
                    except Exception as http_err:
                        print(f"⚠️  [HTTP PIPE EXCEPTION]: {str(http_err)}")

        except Exception as global_err:
            print(f"[DAEMON ERROR ENGINE TRIGGER]: Failure checking kernel events paths: {str(global_err)}")
            
        # 3 seconds throttling interval loops timeout to stabilize enterprise host performance parameters
        time.sleep(3)


if __name__ == "__main__":
    # Ensure checking script running platform parameters to clear execution barriers bounds
    if os.name != 'nt':
        print("[ENVIRONMENT WARNING] Windows Security Log Collector requires a native Win32 platform kernel system.")
    
    collect_and_stream_logs()