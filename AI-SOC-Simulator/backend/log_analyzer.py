import re
from collections import defaultdict, deque
from datetime import datetime, timedelta


class LogAnalyzer:

    def __init__(self):
        # Time-based tracking structures
        self.brute_force_tracker = defaultdict(deque)
        self.port_scan_tracker = defaultdict(deque)
        self.time_window = timedelta(minutes=2)

    # =================================
    # MAIN ANALYSIS PIPELINE
    # =================================
    def analyze_log(self, log_line):
        if not log_line:
            log_line = ""

        timestamp = self._extract_timestamp(log_line)
        source_ip = self._extract_ip(log_line)
        destination_ip = self._extract_destination_ip(log_line)
        username = self._extract_user(log_line)
        event_id = self._extract_event_id(log_line)

        # Baseline parsing framework response layout matching database parameters
        result = {
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "message": log_line,
            "attack_type": "NORMAL",
            "severity": "LOW",
            "threat_score": 0,
            "source_ip": source_ip if source_ip else "0.0.0.0",
            "destination_ip": destination_ip if destination_ip else "0.0.0.0",
            "username": username,
            "event_id": event_id
        }

        log_upper = log_line.upper()

        # =================================
        # WINDOWS FAILED LOGIN / BRUTE FORCE (Event ID 4625)
        # =================================
        if (
            "FAILED LOGIN" in log_upper
            or "LOGIN FAILED" in log_upper
            or "AUDIT FAILURE" in log_upper
            or "EVENTID=4625" in log_upper
            or "ID=4625" in log_upper
            or event_id == "4625"
        ):
            # Target identification block (IP + Username combination crash safety ensure karta hai)
            tracker_key = f"{result['source_ip']}_{result['username']}"
            self._track_failed_login(tracker_key, timestamp)

            count = len(self.brute_force_tracker[tracker_key])

            if count >= 5:
                result.update({
                    "attack_type": "BRUTE_FORCE",
                    "severity": "CRITICAL",
                    "threat_score": 90
                })
            else:
                result.update({
                    "attack_type": "FAILED_LOGIN",
                    "severity": "HIGH",
                    "threat_score": 70
                })

        # =================================
        # SUCCESS LOGIN (Event ID 4624)
        # =================================
        elif (
            "EVENTID=4624" in log_upper
            or "ID=4624" in log_upper
            or event_id == "4624"
            or "SUCCESS_LOGIN" in log_upper
        ):
            result.update({
                "attack_type": "SUCCESSFUL_LOGIN",
                "severity": "LOW",
                "threat_score": 5
            })

        # =================================
        # PROCESS CREATION (Event ID 4688)
        # =================================
        elif (
            "EVENTID=4688" in log_upper
            or "ID=4688" in log_upper
            or event_id == "4688"
            or "PROCESS_CREATED" in log_upper
        ):
            result.update({
                "attack_type": "PROCESS_EXECUTION",
                "severity": "MEDIUM",
                "threat_score": 40
            })

        # =================================
        # POWERSHELL ABUSE DETECTION
        # =================================
        elif (
            "POWERSHELL" in log_upper
            or "ENCODEDCOMMAND" in log_upper
            or "IEX(" in log_upper
        ):
            result.update({
                "attack_type": "POWERSHELL_ABUSE",
                "severity": "HIGH",
                "threat_score": 80
            })

        # =================================
        # PORT SCAN SIGNATURE TRACKING
        # =================================
        elif (
            "PORT_SCAN" in log_upper
            or "NMAP" in log_upper
            or "SCANNER" in log_upper
        ):
            src = result["source_ip"]
            self._track_port_scan(src, timestamp)
            scan_count = len(self.port_scan_tracker[src])

            if scan_count >= 3:
                result.update({
                    "attack_type": "PORT_SCAN",
                    "severity": "CRITICAL",
                    "threat_score": 85
                })
            else:
                result.update({
                    "attack_type": "RECONNAISSANCE",
                    "severity": "MEDIUM",
                    "threat_score": 50
                })

        # =================================
        # MALWARE / TROJAN DETECTION
        # =================================
        elif (
            "MALWARE" in log_upper
            or "TROJAN" in log_upper
            or "VIRUS" in log_upper
            or "BACKDOOR" in log_upper
        ):
            result.update({
                "attack_type": "MALWARE",
                "severity": "CRITICAL",
                "threat_score": 95
            })

        # =================================
        # RANSOMWARE CORRELATION
        # =================================
        elif (
            "RANSOMWARE" in log_upper
            or ".LOCKED" in log_upper
            or ".CRYPT" in log_upper
            or "ENCRYPTED FILES" in log_upper
        ):
            result.update({
                "attack_type": "RANSOMWARE",
                "severity": "CRITICAL",
                "threat_score": 100
            })

        # =================================
        # DATA EXFILTRATION SIGNATURES
        # =================================
        elif (
            "DATA_EXFIL" in log_upper
            or "EXFILTRATION" in log_upper
            or "LARGE DATA TRANSFER" in log_upper
        ):
            result.update({
                "attack_type": "DATA_EXFILTRATION",
                "severity": "CRITICAL",
                "threat_score": 100
            })

        # =================================
        # PRIVILEGE ESCALATION DETECTION
        # =================================
        elif (
            "PRIVILEGE" in log_upper
            or "ADMIN ACCESS" in log_upper
            or "ROOT ACCESS" in log_upper
        ):
            result.update({
                "attack_type": "PRIVILEGE_ESCALATION",
                "severity": "CRITICAL",
                "threat_score": 95
            })

        # =================================
        # SQL INJECTION LOOKUP
        # =================================
        elif (
            "UNION SELECT" in log_upper
            or "' OR '1'='1" in log_upper
            or "SQL INJECTION" in log_upper
        ):
            result.update({
                "attack_type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "threat_score": 95
            })

        # =================================
        # CROSS SITE SCRIPTING (XSS)
        # =================================
        elif (
            "<SCRIPT>" in log_upper
            or "JAVASCRIPT:" in log_upper
        ):
            result.update({
                "attack_type": "XSS_ATTACK",
                "severity": "HIGH",
                "threat_score": 80
            })

        # =================================
        # SUSPICIOUS VARIATION MATCHES
        # =================================
        elif (
            "SUSPICIOUS" in log_upper
            or "ANOMALY" in log_upper
        ):
            result.update({
                "attack_type": "SUSPICIOUS_ACTIVITY",
                "severity": "HIGH",
                "threat_score": 60
            })

        return result

    # =================================
    # INTERNAL SLIDING WINDOW TRACKERS
    # =================================
    def _track_failed_login(self, key, now):
        self.brute_force_tracker[key].append(now)
        while self.brute_force_tracker[key] and (now - self.brute_force_tracker[key][0] > self.time_window):
            self.brute_force_tracker[key].popleft()

    def _track_port_scan(self, ip, now):
        self.port_scan_tracker[ip].append(now)
        while self.port_scan_tracker[ip] and (now - self.port_scan_tracker[ip][0] > self.time_window):
            self.port_scan_tracker[ip].popleft()

    # =================================
    # PARSING ENGINE HELPER REGEXES
    # =================================
    def _extract_timestamp(self, text):
        match = re.search(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", text)
        if match:
            try:
                ts_str = match.group(1).replace('T', ' ')
                return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
        return datetime.now()

    def _extract_ip(self, text):
        # Explicit lookahead logic source IP parameters extraction ke liye
        match = re.search(r"(?:SRC=|SOURCE=|FROM\s+)?\b((?:\d{1,3}\.){3}\d{1,3})\b", text, re.IGNORECASE)
        return match.group(1) if match else "0.0.0.0"

    def _extract_destination_ip(self, text):
        # Destination keywords matching sequence pattern verification
        match = re.search(r"(?:DST=|DEST=|TO\s+)?\b((?:\d{1,3}\.){3}\d{1,3})\b", text, re.IGNORECASE)
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        
        if "DST=" in text.upper() or "DEST=" in text.upper():
            return match.group(1) if match else None
        elif len(ips) >= 2:
            return ips[1]
        return None

    def _extract_user(self, text):
        patterns = [
            r"Account Name:\s*([^\s\|]+)",
            r"User:\s*([^\s\|]+)",
            r"User\s+([^\s\|]+)",
            r"USR=([^\s\|]+)"
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match and match.group(1).strip():
                return match.group(1).strip()
        return "unknown"

    def _extract_event_id(self, text):
        match = re.search(r"\b(?:EVENTID|EVENT ID|ID)\s*[:=]?\s*(\d+)\b", text, re.IGNORECASE)
        return match.group(1) if match else None


# =================================
# PIPELINE STANDALONE DRY-RUN TEST
# =================================
if __name__ == "__main__":
    analyzer = LogAnalyzer()

    # Test frames configurations simulation arrays
    normal_log = "2026-06-15 10:00:00 SOURCE=192.168.1.50 User administrator EVENTID=4624 Successful Login Status"
    attack_log = "2026-06-15 10:02:00 SOURCE=10.0.0.12 User target_user ID=4625 AUDIT FAILURE - FAILED LOGIN ATTEMPT"

    print("--- Normal Log Line Parse Run ---")
    print(analyzer.analyze_log(normal_log))

    print("\n--- Attack Threshold Ingestion Simulation ---")
    # Simulate consecutive quick brute force attempts
    for i in range(6):
        analysis_output = analyzer.analyze_log(attack_log)
    print(analysis_output)