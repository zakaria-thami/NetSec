import json
import uuid
import os
from flask import Blueprint, request, render_template, redirect, url_for,jsonify,session
from datetime import datetime
from analyze_traffic import load_pcap, analyze_packets, classify_attacks
from models.report_manager import ReportManager
import bcrypt
import subprocess
import time

CREDENTIALS_FILE = "credentials.json"
PCAP_DIR = "pcap_files"

os.makedirs(PCAP_DIR, exist_ok=True)

# Define Blueprints
analyze_bp = Blueprint("analyze", __name__)
reports_bp = Blueprint("reports", __name__)
auth_bp = Blueprint("auth",__name__)

REPORTS_FILE = "reports.json"

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
    is_malicious = not ("Benign" in attacks)

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


@analyze_bp.route("/analyze_network", methods=["POST"])
def analyze_network():
    """Runs network capture, analyzes the PCAP, and redirects to the report page."""
    
    # Generate a unique filename based on timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_filename = f"{PCAP_DIR}/capture_{timestamp}.pcap"

    # Run tcpdump_handler.py to capture traffic
    try:
        subprocess.run(["python3", "tcpdump_handler.py", pcap_filename], check=True)
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to run tcpdump_handler.py: {str(e)}"}), 500

    # Wait for the PCAP file to be created (handling potential delays)
    max_wait_time = 61  # seconds
    elapsed_time = 0
    while not os.path.exists(pcap_filename) and elapsed_time < max_wait_time:
        time.sleep(1)  # Wait 1 second
        elapsed_time += 1

    if not os.path.exists(pcap_filename):
        return jsonify({"error": "PCAP file was not created in time."}), 500

    # Analyze the captured traffic
    packets = load_pcap(pcap_filename)
    
    if not packets:
        return jsonify({"error": "No packets found in the capture."}), 400

    results = analyze_packets(packets)
    attacks = classify_attacks(packets)

    # Generate a unique report ID
    report_id = str(uuid.uuid4())

    # Determine if the traffic is malicious
    is_malicious = not ("Benign" in attacks) 

    # Save the report with metadata
    report_data = {
        "report_id": report_id,
        "pcap_filename": pcap_filename,
        "date_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "traffic_analysis": results,
        "attack_classification": attacks,
        "is_malicious": is_malicious
    }
    ReportManager.save_report(report_id, report_data)

    # Redirect to the generated report page
    return redirect(url_for("reports.get_report", report_id=report_id))

@reports_bp.route("/report/<report_id>")
def get_report(report_id):
    
    """Retrieves a report based on report_id."""
    reports = ReportManager.load_reports()
    report_data = reports.get(report_id)

    return render_template("report.html", report=report_data, report_id=report_id)

