import sqlite3
from datetime import datetime

DB_NAME = "soc_logs.db"


class Database:

    def __init__(self):
        # Initial connection sirf tables verify aur create karne ke liye
        conn = self._get_connection()
        self.create_tables(conn)
        conn.close()

    def _get_connection(self):
        """Har thread ke liye ek safe safe fresh connection generate karta hai."""
        conn = sqlite3.connect(DB_NAME, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ==================================
    # CREATE TABLES
    # ==================================
    def create_tables(self, conn):
        cursor = conn.cursor()
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            log_type TEXT,
            attack_type TEXT,
            message TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            username TEXT,
            severity TEXT,
            threat_score INTEGER DEFAULT 0,
            event_id TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_type TEXT,
            start_time TEXT,
            end_time TEXT,
            status TEXT,
            risk_level TEXT,
            details TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT,
            ioc_value TEXT,
            first_seen TEXT
        )
        """)

        conn.commit()

    # ==================================
    # INSERT LOG
    # ==================================
    def insert_log(
        self,
        timestamp,
        log_type,
        message,
        source_ip=None,
        severity="LOW",
        threat_score=0,
        attack_type=None,
        destination_ip=None,
        username=None,
        event_id=None
    ):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO logs(
            timestamp,
            log_type,
            attack_type,
            message,
            source_ip,
            destination_ip,
            username,
            severity,
            threat_score,
            event_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            log_type,
            attack_type,
            message,
            source_ip,
            destination_ip,
            username,
            severity,
            threat_score,
            event_id
        ))

        conn.commit()
        conn.close()

    # ==================================
    # GET ALL LOGS
    # ==================================
    def get_all_logs(self):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        SELECT *
        FROM logs
        ORDER BY id DESC
        """)

        rows = cursor.fetchall()
        result = [dict(row) for row in rows]
        conn.close()
        return result

    # ==================================
    # TOP ATTACKERS
    # ==================================
    def get_top_attackers(self):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        SELECT source_ip,
               COUNT(*) as total
        FROM logs
        WHERE source_ip IS NOT NULL AND source_ip != ''
        GROUP BY source_ip
        ORDER BY total DESC
        LIMIT 10
        """)

        rows = cursor.fetchall()
        result = [
            {
                "ip": row["source_ip"],
                "count": row["total"]
            }
            for row in rows
        ]
        conn.close()
        return result

    # ==================================
    # IOC STORAGE
    # ==================================
    def insert_ioc(self, ioc_type, ioc_value):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO iocs(
            ioc_type,
            ioc_value,
            first_seen
        )
        VALUES (?, ?, ?)
        """, (
            ioc_type,
            ioc_value,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        conn.commit()
        conn.close()

    # ==================================
    # IOC LIST
    # ==================================
    def get_iocs(self):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        SELECT *
        FROM iocs
        ORDER BY id DESC
        """)

        rows = cursor.fetchall()
        result = [dict(row) for row in rows]
        conn.close()
        return result

    # ==================================
    # INCIDENTS
    # ==================================
    def create_incident(
        self,
        incident_type,
        start_time,
        status="OPEN",
        risk_level="HIGH",
        details=""
    ):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO incidents(
            incident_type,
            start_time,
            status,
            risk_level,
            details
        )
        VALUES (?, ?, ?, ?, ?)
        """, (
            incident_type,
            start_time,
            status,
            risk_level,
            details
        ))

        conn.commit()
        conn.close()

    # ==================================
    # RECENT INCIDENTS
    # ==================================
    def get_recent_incidents(self):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        SELECT *
        FROM incidents
        ORDER BY id DESC
        LIMIT 20
        """)

        rows = cursor.fetchall()
        result = [dict(row) for row in rows]
        conn.close()
        return result

    # ==================================
    # TOTAL THREAT SCORE
    # ==================================
    def get_total_threat_score(self):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        SELECT SUM(threat_score)
        FROM logs
        """)

        res = cursor.fetchone()[0]
        conn.close()
        return res if res else 0

    # ==================================
    # DASHBOARD STATS
    # ==================================
    def get_dashboard_stats(self):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM logs")
        total_logs = cursor.fetchone()[0]

        cursor.execute("""
        SELECT COUNT(*)
        FROM logs
        WHERE UPPER(severity)='CRITICAL'
        """)
        critical = cursor.fetchone()[0]

        cursor.execute("""
        SELECT COUNT(DISTINCT source_ip)
        FROM logs
        WHERE source_ip IS NOT NULL AND source_ip != ''
        """)
        unique_ips = cursor.fetchone()[0]

        total_threat = self.get_total_threat_score()
        conn.close()

        return {
            "total_logs": total_logs,
            "critical_events": critical,
            "unique_ips": unique_ips,
            "threat_score": total_threat
        }

    # ==================================
    # SEVERITY BREAKDOWN
    # ==================================
    def get_severity_breakdown(self):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        SELECT severity,
               COUNT(*) as total
        FROM logs
        GROUP BY severity
        """)

        rows = cursor.fetchall()
        result = [
            {
                "severity": row["severity"],
                "count": row["total"]
            }
            for row in rows
        ]
        conn.close()
        return result

    # ==================================
    # TIMELINE DATA
    # ==================================
    def get_timeline_data(self):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        SELECT timestamp,
               threat_score
        FROM logs
        ORDER BY id ASC
        """)

        rows = cursor.fetchall()
        result = [
            {
                "timestamp": row["timestamp"],
                "score": row["threat_score"]
            }
            for row in rows
        ]
        conn.close()
        return result


if __name__ == "__main__":
    db = Database()

    db.insert_log(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        log_type="SYSTEM",
        attack_type="INFO",
        message="SOC System Started",
        source_ip="127.0.0.1",
        severity="LOW",
        threat_score=0
    )

    print("SOC Database Ready & Fully Thread-Safe!")