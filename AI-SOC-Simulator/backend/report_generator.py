
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak
)

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

from datetime import datetime


class SOCReportGenerator:

    def __init__(
        self,
        filename="SOC_Incident_Report.pdf"
    ):

        self.filename = filename

        self.styles = getSampleStyleSheet()

    # ==================================
    # MAIN REPORT
    # ==================================
    def generate_report(
        self,
        incident_data
    ):

        doc = SimpleDocTemplate(
            self.filename
        )

        elements = []

        title = Paragraph(
            "<b>AI SOC INCIDENT REPORT</b>",
            self.styles["Title"]
        )

        elements.append(title)
        elements.append(
            Spacer(1, 12)
        )

        generated = Paragraph(
            f"""
            Generated:
            {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """,
            self.styles["Normal"]
        )

        elements.append(generated)

        elements.append(
            Spacer(1, 20)
        )

        # ==================================
        # INCIDENT DETAILS
        # ==================================
        elements.append(
            Paragraph(
                "<b>Incident Details</b>",
                self.styles["Heading2"]
            )
        )

        details = f"""
        Incident ID:
        {incident_data.get('incident_id','N/A')}
        <br/>
        Risk Level:
        {incident_data.get('risk_level','UNKNOWN')}
        <br/>
        Start Time:
        {incident_data.get('start_time','N/A')}
        """

        elements.append(
            Paragraph(
                details,
                self.styles["Normal"]
            )
        )

        elements.append(
            Spacer(1, 15)
        )

        # ==================================
        # EXECUTIVE SUMMARY
        # ==================================
        elements.append(
            Paragraph(
                "<b>Executive Summary</b>",
                self.styles["Heading2"]
            )
        )

        summary = incident_data.get(
            "summary",
            "No summary available."
        )

        elements.append(
            Paragraph(
                summary,
                self.styles["BodyText"]
            )
        )

        elements.append(
            Spacer(1, 15)
        )

        # ==================================
        # ATTACK TYPES
        # ==================================
        elements.append(
            Paragraph(
                "<b>Detected Attack Types</b>",
                self.styles["Heading2"]
            )
        )

        attacks = incident_data.get(
            "attack_types",
            []
        )

        if attacks:

            for attack in attacks:

                elements.append(
                    Paragraph(
                        f"• {attack}",
                        self.styles["Normal"]
                    )
                )

        else:

            elements.append(
                Paragraph(
                    "No attack types detected",
                    self.styles["Normal"]
                )
            )

        elements.append(
            Spacer(1, 15)
        )

        # ==================================
        # IOC SECTION
        # ==================================
        elements.append(
            Paragraph(
                "<b>Indicators of Compromise (IOC)</b>",
                self.styles["Heading2"]
            )
        )

        iocs = incident_data.get(
            "iocs",
            []
        )

        if iocs:

            for item in iocs:

                elements.append(
                    Paragraph(
                        f"• {item}",
                        self.styles["Normal"]
                    )
                )

        else:

            elements.append(
                Paragraph(
                    "No IOC extracted",
                    self.styles["Normal"]
                )
            )

        elements.append(
            Spacer(1, 15)
        )

        # ==================================
        # TOP ATTACKERS
        # ==================================
        elements.append(
            Paragraph(
                "<b>Top Attacker IPs</b>",
                self.styles["Heading2"]
            )
        )

        attackers = incident_data.get(
            "top_attackers",
            []
        )

        if attackers:

            for attacker in attackers:

                elements.append(
                    Paragraph(
                        str(attacker),
                        self.styles["Normal"]
                    )
                )

        else:

            elements.append(
                Paragraph(
                    "No attacker IPs detected",
                    self.styles["Normal"]
                )
            )

        elements.append(
            Spacer(1, 15)
        )

        # ==================================
        # SEVERITY STATS
        # ==================================
        elements.append(
            Paragraph(
                "<b>Severity Breakdown</b>",
                self.styles["Heading2"]
            )
        )

        severity_stats = incident_data.get(
            "severity_breakdown",
            {}
        )

        if severity_stats:

            for key, value in severity_stats.items():

                elements.append(
                    Paragraph(
                        f"{key}: {value}",
                        self.styles["Normal"]
                    )
                )

        else:

            elements.append(
                Paragraph(
                    "No severity statistics available",
                    self.styles["Normal"]
                )
            )

        elements.append(
            Spacer(1, 15)
        )

        # ==================================
        # RECOMMENDATIONS
        # ==================================
        elements.append(
            Paragraph(
                "<b>Recommendations</b>",
                self.styles["Heading2"]
            )
        )

        recommendations = [

            "Investigate all critical alerts immediately.",

            "Review failed login activity and enforce MFA.",

            "Monitor suspicious PowerShell execution.",

            "Block malicious IP addresses.",

            "Review endpoint security posture.",

            "Perform malware scans across affected hosts."
        ]

        for rec in recommendations:

            elements.append(
                Paragraph(
                    f"• {rec}",
                    self.styles["Normal"]
                )
            )

        elements.append(
            PageBreak()
        )

        # ==================================
        # EVIDENCE LOGS
        # ==================================
        elements.append(
            Paragraph(
                "<b>Evidence Logs</b>",
                self.styles["Heading1"]
            )
        )

        logs = incident_data.get(
            "logs",
            []
        )

        for log in logs[:100]:

            elements.append(
                Paragraph(
                    str(log),
                    self.styles["Code"]
                )
            )

        doc.build(elements)

        return self.filename


# ==================================
# TEST
# ==================================
if __name__ == "__main__":

    report = SOCReportGenerator()

    sample = {

        "incident_id": "INC-1001",

        "risk_level": "CRITICAL",

        "start_time": "2026-06-15 10:30:00",

        "summary":
        "Multiple brute force and malware events detected.",

        "attack_types": [
            "BRUTE_FORCE",
            "MALWARE",
            "POWERSHELL_ABUSE"
        ],

        "iocs": [
            "192.168.1.100",
            "malicious.exe",
            "Trojan.Win32"
        ],

        "top_attackers": [
            "192.168.1.100",
            "10.10.10.5"
        ],

        "severity_breakdown": {
            "CRITICAL": 10,
            "HIGH": 15,
            "MEDIUM": 22,
            "LOW": 35
        },

        "logs": [
            "Failed login detected",
            "PowerShell suspicious command",
            "Malware execution detected"
        ]
    }

    file = report.generate_report(
        sample
    )

    print(
        f"Report Generated: {file}"
    )
