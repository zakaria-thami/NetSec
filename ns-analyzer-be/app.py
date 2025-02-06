import os
from flask import Flask, render_template, send_from_directory
import json
from flask_cors import CORS
from dotenv import load_dotenv
from routes import analyze_bp, reports_bp
from models.report_manager import ReportManager

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

with open('credentials.json', 'r') as f:
    credentials = json.load(f)


# Register the API Blueprint
app.register_blueprint(analyze_bp, url_prefix="/api")
app.register_blueprint(reports_bp, url_prefix="/api")

@app.route("/home")
def home():
    """Serve the main home page"""
    return render_template("home.html")

@app.route("/devices")
def devices():
    """Serve the display of discovered devices."""
    return render_template("devices.html")

@app.route("/reports")
def reports():
    """Renders the reports page with metadata from saved reports."""
    reports_data = ReportManager.load_reports()
    reports_list = []

    for report_id, data in reports_data.items():
        date_time = data.get("date_time", "Unknown")
        packet_count = sum(data.get("traffic_analysis", {}).get("protocol_counts", {}).values())
        is_malicious = data.get("is_malicious", False)
        flag = "Hostile" if is_malicious else "Benign"

        reports_list.append({
            "report_id": report_id,
            "report_name": f"Report {report_id[:8]}",
            "date_time": date_time,
            "packet_count": packet_count,
            "flag": flag
        })

    return render_template("reports.html", reports=reports_list)

@app.route("/")
def login():
    """Serve the login page."""
    return render_template("login.html") 


@app.route("/static/<path:filename>")
def serve_static(filename):
    """Serve static files like CSS, JS, and images."""
    return send_from_directory("static", filename)

if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", 4000))
    app.run(debug=True, host="0.0.0.0", port=port)
