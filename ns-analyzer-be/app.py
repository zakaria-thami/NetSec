import os
from flask import Flask, render_template, send_from_directory
import json
from flask_cors import CORS
from dotenv import load_dotenv
from routes import analyze_bp, reports_bp , auth_bp
from models.report_manager import ReportManager
from models.device_manager import DeviceManager, scan_network
from network_info import get_network_info

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = "test123"
CORS(app)


with open('credentials.json', 'r') as f:
    credentials = json.load(f)


# Register the API Blueprint
app.register_blueprint(analyze_bp, url_prefix="/api")
app.register_blueprint(reports_bp, url_prefix="/api")
app.register_blueprint(auth_bp, url_prefix='/auth')

@app.route("/")
def login():
    """Serve the login page."""
    return render_template("login.html") 

@app.route("/home")
def home():
    network_data = get_network_info()
    return render_template("home.html", network=network_data)
 

@app.route("/devices")
def devices():
    """Serve the display of discovered devices."""
    devices_data=scan_network()
    
    
    return render_template("devices.html", devices=devices_data)
    



@app.route("/history")
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

    return render_template("history.html", reports=reports_list)




@app.route("/static/<path:filename>")
def serve_static(filename):
    """Serve static files like CSS, JS, and images."""
    return send_from_directory("static", filename)

if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", 4000))
    app.run(debug=True, host="0.0.0.0", port=port)
