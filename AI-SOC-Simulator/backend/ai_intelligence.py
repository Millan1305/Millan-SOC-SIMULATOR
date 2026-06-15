from collections import defaultdict, deque
from datetime import datetime, timedelta


class SOCIntelligence:

    def __init__(self):
        # Time-based event storage window configuration
        self.event_window = defaultdict(deque)
        self.window_size = timedelta(minutes=3)

    # =========================
    # MITRE ATT&CK MAPPING
    # =========================
    def mitre_map(self, attack_type):
        """Maps incoming security attack types to official MITRE ATT&CK Framework matrix."""
        if not attack_type:
            return "UNKNOWN"
            
        mapping = {
            "BRUTE_FORCE": "T1110 - Credential Access",
            "PORT_SCAN": "T1046 - Discovery (Network Scanning)",
            "BLACKLISTED_IP": "T1078 - Valid Accounts Abuse",
            "SUSPICIOUS_ACTIVITY": "T1068 - Privilege Escalation",
            "MALWARE": "T1204 - Malicious Execution",
            "RANSOMWARE": "T1486 - Data Encryption Impact",
            "DATA_EXFILTRATION": "T1041 - Exfiltration Over Network",
            "POWERSHELL_ABUSE": "T1059.001 - PowerShell Execution"
        }

        # Case insensitive mapping match setup
        return mapping.get(str(attack_type).upper(), "UNKNOWN")

    # =========================
    # REAL ATTACK CORRELATION ENGINE
    # =========================
    def correlate_events(self, logs):
        """
        SOC-Level Evaluation:
        Detect multi-stage attack campaigns using real-time sliding time window.
        """
        campaigns = []
        temp_window = deque()

        if not logs:
            return campaigns

        for log in logs:
            # Normalize dict format validation frame
            if isinstance(log, dict):
                event = log
            else:
                continue

            temp_window.append(event)

            # Old events clear out karna sliding metrics calculation frame se
            self._cleanup(temp_window)

            # Attack configuration signatures compile karna safely
            attack_types = set(str(e.get("log_type", "")).upper() for e in temp_window if e.get("log_type"))

            # MULTI-STAGE ATTACK DETECTION (Kill-Chain Simulation)
            if len(attack_types) >= 3:
                campaigns.append({
                    "campaign_type": "MULTI_STAGE_ATTACK",
                    "event_count": len(temp_window),
                    "events": list(temp_window),
                    "risk": "CRITICAL",
                    "description": "Multi-vector campaign signatures detected inside the timeline slice."
                })
                temp_window.clear()

        return campaigns

    # =========================
    # ANOMALY SCORE ENGINE
    # =========================
    def anomaly_score(self, event_count, unique_ips, critical_events):
        """Calculates security threat matrix metrics parameters score."""
        score = (
            int(event_count or 0) * 1 +
            int(unique_ips or 0) * 6 +
            int(critical_events or 0) * 12
        )

        if score > 500:
            level = "CRITICAL"
        elif score > 250:
            level = "HIGH"
        elif score > 100:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "score": score,
            "level": level
        }

    # =========================
    # INCIDENT TIMELINE BUILDER
    # =========================
    def build_timeline(self, logs):
        """Assembles chronologically structured analytics array blocks."""
        timeline = []
        if not logs:
            return timeline

        for log in logs:
            if isinstance(log, dict):
                timeline.append({
                    "time": log.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "event": log.get("log_type") or log.get("attack_type") or "GENERIC_EVENT",
                    "severity": str(log.get("severity", "LOW")).upper()
                })

        # Return safe string mapping sorted layout validation frame
        return sorted(timeline, key=lambda x: str(x["time"]))

    # =========================
    # AI SOC SUMMARY GENERATOR
    # =========================
    def generate_summary(self, logs):
        """Processes global logs vector sets to build AI insights metrics layout."""
        attack_count = defaultdict(int)
        severity_count = defaultdict(int)

        if not logs:
            return {
                "total_events": 0,
                "top_attacks": [],
                "severity_distribution": {},
                "insight": "No active telemetry feeds reported inside database storage segments."
            }

        total = len(logs)

        for log in logs:
            if isinstance(log, dict):
                # Fallback matching architecture validation sets
                l_type = log.get("log_type") or log.get("attack_type") or "UNKNOWN"
                sev = str(log.get("severity", "LOW")).upper()
                
                attack_count[l_type] += 1
                severity_count[sev] += 1

        top_attacks = sorted(attack_count.items(), key=lambda x: x[1], reverse=True)[:3]

        summary = {
            "total_events": total,
            "top_attacks": top_attacks,
            "severity_distribution": dict(severity_count),
            "insight": self._create_insight(top_attacks)
        }

        return summary

    # =========================
    # INSIGHT ENGINE
    # =========================
    def _create_insight(self, top_attacks):
        """Assembles AI analytics sentences directly for the UI glass viewport."""
        if not top_attacks:
            return "No significant security threats currently evaluated."

        insights = []

        for attack, count in top_attacks:
            mitre = self.mitre_map(attack)
            insights.append(f"{attack} (Occurrences: {count}) mapped via {mitre}")

        return "AI Analysis Framework Alert: " + " | ".join(insights)

    # =========================
    # CLEANUP FUNCTION (TIME WINDOW)
    # =========================
    def _cleanup(self, window):
        """Trims old logs dynamically from streaming pipeline queue allocations."""
        now = datetime.now()

        while window:
            first = window[0]
            ts = first.get("timestamp")

            if not ts:
                # Agar timestamp missing hai, process bypass karke aage badhein
                window.popleft()
                continue

            # String format ko object parsing architecture provide karna dynamically
            if isinstance(ts, str):
                try:
                    ts = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    try:
                        ts = datetime.fromisoformat(ts)
                    except ValueError:
                        # Fallback parsing format execution frame mismatch edge cases ke liye
                        window.popleft()
                        continue

            elif isinstance(ts, datetime):
                pass  # Already a datetime object wrapper block
            else:
                window.popleft()
                continue

            # Window frame check delta time parameters
            if (now - ts) > self.window_size:
                window.popleft()
            else:
                break


# =========================
# STANDALONE PIPELINE DRY-RUN TEST
# =========================
if __name__ == "__main__":
    ai = SOCIntelligence()

    # Mix string dates and raw datetime wrappers inside simulation logs pipeline
    sample_logs = [
        {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "log_type": "BRUTE_FORCE", "severity": "CRITICAL"},
        {"timestamp": datetime.now(), "log_type": "PORT_SCAN", "severity": "HIGH"},
        {"timestamp": datetime.now(), "log_type": "MALWARE", "severity": "CRITICAL"},
    ]

    print("--- Executive Summary Run ---")
    print(ai.generate_summary(sample_logs))
    print("\n--- MITRE Mapping Dry Run Test ---")
    print(ai.mitre_map("BRUTE_FORCE"))