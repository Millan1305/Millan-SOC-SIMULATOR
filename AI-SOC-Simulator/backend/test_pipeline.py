from system_log_collector import SystemLogCollector
from database import Database
from log_analyzer import LogAnalyzer

collector = SystemLogCollector()
db = Database()
analyzer = LogAnalyzer()

events = collector.get_recent_events(10)

for event in events:

    log_line = event["event_name"]

    analysis = analyzer.analyze_log(log_line)

    db.insert_log(
        timestamp=event["timestamp"],
        log_type=event["event_name"],
        message=str(event["details"]),
        source_ip=None,
        severity=analysis["severity"],
        threat_score=analysis["threat_score"]
    )

    print(
        f"Saved: {event['event_name']} | "
        f"{analysis['severity']}"
    )

print("Done")