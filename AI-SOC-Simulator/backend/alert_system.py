import smtplib
from email.mime.text import MIMEText
from datetime import datetime


class AlertSystem:

    def __init__(self):
        self.alert_log = []

    # =========================
    # GENERATE ALERT
    # =========================
    def create_alert(self, attack_type, severity, score, target_ip=None):

        alert = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_type": attack_type,
            "severity": severity,
            "score": score,
            "target_ip": target_ip
        }

        self.alert_log.append(alert)

        print("🚨 ALERT GENERATED:", alert)

        return alert

    # =========================
    # EMAIL ALERT (OPTIONAL)
    # =========================
    def send_email_alert(self, alert):

        try:
            sender = "your_email@gmail.com"
            password = "your_app_password"
            receiver = "admin_email@gmail.com"

            msg = MIMEText(f"""
SOC ALERT SYSTEM

Time: {alert['time']}
Attack: {alert['attack_type']}
Severity: {alert['severity']}
Score: {alert['score']}
Target IP: {alert['target_ip']}
""")

            msg["Subject"] = "🚨 SOC Security Alert"
            msg["From"] = sender
            msg["To"] = receiver

            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, receiver, msg.as_string())
            server.quit()

            print("Email alert sent")

        except Exception as e:
            print("Email failed:", e)

    # =========================
    # GET ALL ALERTS
    # =========================
    def get_alerts(self):
        return self.alert_log