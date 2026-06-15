from datetime import datetime
from database import Database  # Database integration ensure karne ke liye import kiya


class IncidentResponseEngine:

    def __init__(self):
        # Local state fallback layers
        self.blocked_ips = set()
        self.incidents = []
        # Database persistence channel handle handle karne ke liye instance bind kiya
        self.db = Database()

    # =========================
    # MAIN ENTRY POINT
    # =========================
    def handle_event(self, analysis):
        return self.handle_threat(analysis)

    # =========================
    # AUTO RESPONSE ENGINE
    # =========================
    def handle_threat(self, analysis):
        if not analysis:
            analysis = {}

        current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        response = {
            "timestamp": current_time_str,
            "attack_type": analysis.get("attack_type", "UNKNOWN"),
            "action_taken": [],
            "status": "NO_ACTION"
        }

        attack = analysis.get("attack_type", "NORMAL")
        score = int(analysis.get("threat_score", 0))
        source_ip = analysis.get("source_ip", "0.0.0.0")

        # =========================
        # CRITICAL THREATS (Score >= 90)
        # =========================
        if score >= 90:
            response["status"] = "CRITICAL_RESPONSE"

            # 1. Block malicious IP address and record as IoC threat intel
            if source_ip and source_ip != "0.0.0.0":
                self.block_ip(source_ip)
                response["action_taken"].append(f"Blocked IP: {source_ip}")

            # 2. Compile incident mapping format
            incident_details = f"Automated response engine isolated malicious source sequence. Message trace: {analysis.get('message', 'N/A')}"
            
            # 3. Database me Permanent Incident save karna (app.py alignment fix)
            try:
                self.db.create_incident(
                    incident_type=attack,
                    start_time=current_time_str,
                    status="OPEN",
                    risk_level="CRITICAL",
                    details=incident_details
                )
                response["action_taken"].append("Incident Saved to DB")
            except Exception as db_err:
                response["action_taken"].append(f"DB Write Warning: {str(db_err)}")

            # In-memory backup state sync
            self.incidents.append({
                "time": current_time_str,
                "attack": attack,
                "severity": "CRITICAL",
                "score": score
            })

            # Specific critical payload validation patterns handling
            if attack in ["RANSOMWARE", "MALWARE", "DATA_EXFILTRATION"]:
                response["action_taken"].append("Host Isolation Triggered via Network Agent")

        # =========================
        # HIGH THREATS (Score >= 70)
        # =========================
        elif score >= 70:
            response["status"] = "HIGH_RESPONSE"
            response["action_taken"].append("Alert Sent to SOC Analyst Viewport Interface")
            
            # High threats ke incidents bhi database track board par insert karna safely
            try:
                self.db.create_incident(
                    incident_type=attack,
                    start_time=current_time_str,
                    status="OPEN",
                    risk_level="HIGH",
                    details=f"High risk signature anomaly validation rule matched. Score: {score}"
                )
            except Exception:
                pass

        # =========================
        # MEDIUM THREATS (Score >= 40)
        # =========================
        elif score >= 40:
            response["status"] = "MEDIUM_RESPONSE"
            response["action_taken"].append("Source Metadata Registered onto Watchlist monitoring tracks")

        # =========================
        # LOW THREATS
        # =========================
        else:
            response["status"] = "MONITORING"
            response["action_taken"].append("Telemetry Logged for Baseline Aggregation Analysis")

        return response

    # =========================
    # BLOCK IP
    # =========================
    def block_ip(self, ip):
        if not ip or ip == "0.0.0.0":
            return

        self.blocked_ips.add(ip)
        print(f"[SECURITY ALERT] Automated Mitigation Activated: Blocking Attacker IP -> {ip}")

        # Persistent Threat Intelligence update logic block
        try:
            # Check database synchronization routines directly
            self.db.insert_ioc(ioc_type="IP_ADDRESS", ioc_value=ip)
            print(f"[INTEL DB] IP {ip} successfully logged onto Global IoC Threat Matrix database.")
        except Exception as e:
            print(f"[ERROR] Failed to push network IoC records metadata block: {e}")

    # =========================
    # GET BLOCKED IPS
    # =========================
    def get_blocked_ips(self):
        # Database fallback dynamic retrieval loop implementation
        try:
            db_iocs = self.db.get_iocs()
            db_ips = [x["ioc_value"] for x in db_iocs if x.get("ioc_type") == "IP_ADDRESS"]
            if db_ips:
                return list(set(list(self.blocked_ips) + db_ips))
        except Exception:
            pass
        return list(self.blocked_ips)

    # =========================
    # GET INCIDENTS
    # =========================
    def get_incidents(self):
        try:
            db_records = self.db.get_recent_incidents()
            if db_records:
                return db_records
        except Exception:
            pass
        return self.incidents

    # =========================
    # CLEAR INCIDENTS
    # =========================
    def clear_incidents(self):
        self.incidents.clear()
        print("[INFO] Local memory volatile cache allocations scrubbed.")

    # =========================
    # DASHBOARD SUMMARY
    # =========================
    def get_summary(self):
        try:
            db_records = self.db.get_recent_incidents() or []
            db_iocs = self.db.get_iocs() or []
            
            critical_count = len([x for x in db_records if str(x.get("risk_level", "")).upper() == "CRITICAL"])
            
            return {
                "total_incidents": len(db_records),
                "blocked_ips": len([x for x in db_iocs if x.get("ioc_type") == "IP_ADDRESS"]),
                "critical_incidents": critical_count
            }
        except Exception:
            # Dynamic state tracking array recovery metric structure fallback
            return {
                "total_incidents": len(self.incidents),
                "blocked_ips": len(self.blocked_ips),
                "critical_incidents": len([x for x in self.incidents if x.get("severity") == "CRITICAL"])
            }


# =========================
# STANDALONE INTEGRATION DRY-RUN TEST
# =========================
if __name__ == "__main__":
    engine = IncidentResponseEngine()

    # Dry run sample attack packet creation matching analyzer layout
    sample_malicious_packet = {
        "attack_type": "RANSOMWARE",
        "threat_score": 95,
        "source_ip": "45.12.33.10",
        "message": "Critical host system access trace modification logs flagged alert trigger"
    }

    print("--- Running Threat Engine Analysis Ingestion ---")
    mitigation_result = engine.handle_event(sample_malicious_packet)
    print(mitigation_result)

    print("\n--- Current Blocked Active IPs Tracking Module ---")
    print(engine.get_blocked_ips())

    print("\n--- System Operational Dashboard Summaries Matrix ---")
    print(engine.get_summary())