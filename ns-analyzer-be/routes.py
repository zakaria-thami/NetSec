import json
import uuid
import os
from flask import Blueprint, request, render_template, redirect, url_for,jsonify,session
from datetime import datetime
from analyze_traffic import load_pcap, analyze_packets, classify_attacks
from models.report_manager import ReportManager
import bcrypt


CREDENTIALS_FILE = "credentials.json"

# Define Blueprints
analyze_bp = Blueprint("analyze", __name__)
reports_bp = Blueprint("reports", __name__)
auth_bp = Blueprint("auth",__name__)

def load_credentials():
    try:
        with open(CREDENTIALS_FILE, "r") as file:
            data = json.load(file)
        return data.get("users", [])
    except (FileNotFoundError, json.JSONDecodeError) as e:
        return []

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check credentials
        users = load_credentials()
        print(users)
        for user in users:
            if user["username"] == username:
                stored_hash = user["password"]
                if bcrypt.checkpw(password.encode(), stored_hash.encode()):
                    # Store user info in session
                    session['username'] = username
                    return redirect(url_for('home'))  # Redirect to home page on success
                else:
                    return render_template('login.html', error="Invalid username or password.")
        
        return render_template('login.html', error="Invalid username or password.")
    
    return render_template('login.html')  # GET request renders the login form

# JSON file to store reports
REPORTS_FILE = "reports.json"

@analyze_bp.route("/test_for_exam", methods=["POST"])
def test_for_exam():
    """Analyzes the PCAP file and redirects to the report page."""
    filename = request.form.get("filename", "merged_output.pcap")
    packets = load_pcap(filename)

    # Perform analysis
    results = analyze_packets(packets)
    attacks = classify_attacks(packets)

    # Generate a unique report ID
    report_id = str(uuid.uuid4())

    # Determine if the traffic is malicious based on attack classification
    is_malicious = bool(attacks)  # True if attack_classification is not empty

    # Save report with additional metadata
    report_data = {
        "report_id": report_id,
        "date_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "traffic_analysis": results,
        "attack_classification": attacks,
        "is_malicious": is_malicious  # Flag for malicious detection
    }
    ReportManager.save_report(report_id, report_data)

    return redirect(url_for("reports.get_report", report_id=report_id))

@reports_bp.route("/report/<report_id>")
def get_report(report_id):
    
    """Retrieves a report based on report_id."""
    reports = ReportManager.load_reports()
    report_data = reports.get(report_id)

    return render_template("report.html", report=report_data, report_id=report_id)

