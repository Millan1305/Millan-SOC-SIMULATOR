from system_log_collector import SystemLogCollector

collector = SystemLogCollector()

logs = collector.get_recent_events()

for log in logs:
    print(log)