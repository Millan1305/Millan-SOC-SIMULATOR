from flask import Flask, request, jsonify, send_from_directory
from datetime import datetime
from flask_cors import CORS
import os

# Core application subsystem modules import
from database import Database
from log_analyzer import LogAnalyzer
from ai_intelligence import SOCIntelligence
from geo_intelligence import GeoIntelligence
from incident_response import IncidentResponseEngine
from auth import AuthSystem

# Flask app initialization configuration
app = Flask(
    __name__,
    static_folder="../frontend",
    static_url_path=""
)

# Cross-Origin Resource Sharing (CORS) bypass activation
# Taaki agar frontend external framework se chal raha ho, toh browser block na kare
CORS(app)

# Core objects initialization
db = Database()
analyzer = LogAnalyzer()
ai = SOCIntelligence()
geo = GeoIntelligence()
incident = IncidentResponseEngine()
auth = AuthSystem()


@app.route("/")
def home():
    """Base API health connectivity status endpoint."""
    return jsonify({
        "status": "AI-SOC Core Running",
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "version": "2.4.0"
    })


@app.route("/dashboard")
def dashboard():
    """Serves the primary visual dashboard interface glass plane.

    URL: http://localhost:5000/dashboard
    """
    if not os.path.exists(os.path.join(app.static_folder, "index.html")):
        return jsonify({
            "error": "Frontend assets not found inside directories hierarchy.",
            "tip": f"Please verify that your html files exist at path: {app.static_folder}"
        }), 404
        
    return send_from_directory(app.static_folder, "index.html")


@app.route("/login", methods=["POST"])
def login():
    """Secure analyst authentication validation panel."""
    try:
        data = request.json or {}
        
        result = auth.login(
            data.get("username"),
            data.get("password")
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/ingest-log", methods=["POST"])
def ingest_log():
    """Real-time network telemetry processing pipe engine.

    Parses raw strings strings, updates metrics database, and triggers automated firewalls blocks.
    """
    try:
        data = request.json or {}
        log_line = data.get("log")

        if not log_line or not str(log_line).strip():
            return jsonify({"error": "No log provided"}), 400

        # 1. Raw threat logging text evaluation via log_analyzer.py regex engines
        analysis = analyzer.analyze_log(log_line)

        # 2. Sequential structured argument mapping into thread-safe database.py tables
        db.insert_log(
            timestamp=analysis.get("timestamp"),
            log_type=analysis.get("attack_type", "SYSTEM"),
            message=str(log_line).strip(),
            source_ip=analysis.get("source_ip", "0.0.0.0"),
            severity=analysis.get("severity", "LOW"),
            threat_score=int(analysis.get("threat_score", 0)),
            attack_type=analysis.get("attack_type", "NORMAL"),
            destination_ip=analysis.get("destination_ip", "0.0.0.0"),
            username=analysis.get("username", "unknown"),
            event_id=analysis.get("event_id")
        )

        # 3. Active Mitigation Countermeasure orchestration via incident_response.py hooks
        response = incident.handle_threat(analysis)

        return jsonify({
            "status": "processed",
            "analysis": analysis,
            "response": response
        })

    except Exception as e:
        print("!!! DETAILED PIPELINE INGESTION CRASH TRACE !!! ->", str(e))
        return jsonify({
            "error": "Log ingestion pipeline failed execution parameters.",
            "details": str(e)
        }), 500


@app.route("/logs")
def logs():
    """Historical data layers retrieval route."""
    try:
        return jsonify(db.get_all_logs())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/threat-summary")
def threat_summary():
    """AI engine global contextual aggregation metrics overview compilation."""
    try:
        logs_data = db.get_all_logs()
        return jsonify(ai.generate_summary(logs_data))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/top-attackers")
def top_attackers():
    """Identify highest frequency aggressive adversary nodes."""
    try:
        return jsonify({
            "attackers": db.get_top_attackers()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/geo-data")
def geo_data():
    """Map coordinates metadata tracking pipelines."""
    try:
        logs_data = db.get_all_logs()
        return jsonify(geo.analyze_ips(logs_data))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/dashboard-stats")
def dashboard_stats():
    """Live analytic counter metrics panel synchronizer."""
    try:
        logs_data = db.get_all_logs() or []

        total_logs = len(logs_data)
        
        # Upper case matching structures safe conditional loop calculation checks
        critical = len([x for x in logs_data if str(x.get("severity", "")).upper() == "CRITICAL"])
        high = len([x for x in logs_data if str(x.get("severity", "")).upper() == "HIGH"])
        medium = len([x for x in logs_data if str(x.get("severity", "")).upper() == "MEDIUM"])
        low = len([x for x in logs_data if str(x.get("severity", "")).upper() == "LOW"])

        # Thread safe numerical calculation block for dynamic risk gauge scaling
        try:
            total_threat = db.get_total_threat_score()
        except Exception:
            total_threat = sum([float(x.get("threat_score", 0)) for x in logs_data])

        return jsonify({
            "total_logs": total_logs,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "threat_score": total_threat
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("\n=========================================================")
    print("🚀 SOC SECURITY OPERATION PLATFORM ENGINE ONLINE")
    print("📡 Local Server Port Gateway API: http://localhost:5000")
    print("🖥️  Main UI Dashboard Viewport:  http://localhost:5000/dashboard")
    print("=========================================================\n")

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )