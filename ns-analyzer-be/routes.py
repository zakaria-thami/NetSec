import json
import uuid
import os
from flask import Blueprint, request, render_template, redirect, url_for, jsonify, session
from datetime import datetime
from analyze_traffic import load_pcap, analyze_packets, classify_attacks
from models.report_manager import ReportManager
import bcrypt
import subprocess
import time

# Constants
CREDENTIALS_FILE = "credentials.json"
PCAP_DIR = "pcap_files"

# Ensure the PCAP directory exists
os.makedirs(PCAP_DIR, exist_ok=True)

# Define Flask Blueprints
analyze_bp = Blueprint("analyze", __name__)  # Handles analysis routes
reports_bp = Blueprint("reports", __name__)  # Handles report-related routes
auth_bp = Blueprint("auth", __name__)  # Handles authentication routes

REPORTS_FILE = "reports.json"


### Authentication Handling ###
def load_credentials():
    """Loads user credentials from the JSON file."""
    try:
        with open(CREDENTIALS_FILE, "r") as file:
            data = json.load(file)
        return data.get("users", [])
    except (FileNotFoundError, json.JSONDecodeError) as e:
        return []  # Return empty list if credentials file is missing or corrupted


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login authentication."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Load credentials
        users = load_credentials()
        print(users)
        for user in users:
            if user["username"] == username:
                stored_hash = user["password"]
                if bcrypt.checkpw(password.encode(), stored_hash.encode()):
                    # Store user session
                    session['username'] = username
                    return redirect(url_for('home'))  # Redirect to home page on success
                else:
                    return render_template('login.html', error="Invalid username or password.")
        
        return render_template('login.html', error="Invalid username or password.")
    
    return render_template('login.html')  # Render login form for GET request


### Manual PCAP File Analysis ###
@analyze_bp.route("/test_for_exam", methods=["POST"])
def test_for_exam():
    """Analyzes an existing PCAP file and redirects to the generated report page."""
    filename = request.form.get("filename", "merged_output.pcap")
    packets = load_pcap(filename)

    # Perform analysis on loaded packets
    results = analyze_packets(packets)
    attacks = classify_attacks(packets)

    # Generate a unique report ID
    report_id = str(uuid.uuid4())

    # Determine if the traffic is malicious (True if no "Benign" label)
    is_malicious = not ("Benign" in attacks)

    # Save report with metadata
    report_data = {
        "report_id": report_id,
        "date_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "traffic_analysis": results,
        "attack_classification": attacks,
        "is_malicious": is_malicious  # Flag for malicious detection
    }
    ReportManager.save_report(report_id, report_data)

    return redirect(url_for("reports.get_report", report_id=report_id))


### Live Network Traffic Capture & Analysis ###
@analyze_bp.route("/analyze_network", methods=["POST"])
def analyze_network():
    """
    Runs live network traffic capture using tcpdump, 
    analyzes the PCAP file, and redirects to the generated report page.
    """

    # Generate a unique filename based on timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_filename = f"{PCAP_DIR}/capture_{timestamp}.pcap"

    # Run tcpdump_handler.py to capture traffic
    try:
        subprocess.run(["python3", "tcpdump_handler.py", pcap_filename], check=True)
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to run tcpdump_handler.py: {str(e)}"}), 500

    # Wait for the PCAP file to be created (handling potential delays)
    max_wait_time = 61  # Maximum wait time in seconds
    elapsed_time = 0
    while not os.path.exists(pcap_filename) and elapsed_time < max_wait_time:
        time.sleep(1)  # Wait 1 second
        elapsed_time += 1

    if not os.path.exists(pcap_filename):
        return jsonify({"error": "PCAP file was not created in time."}), 500

    # Load and analyze the captured PCAP file
    packets = load_pcap(pcap_filename)
    
    if not packets:
        return jsonify({"error": "No packets found in the capture."}), 400

    results = analyze_packets(packets)
    attacks = classify_attacks(packets)

    # Generate a unique report ID
    report_id = str(uuid.uuid4())

    # Determine if the traffic is malicious (True if no "Benign" label)
    is_malicious = not ("Benign" in attacks)

    # Save the report with metadata
    report_data = {
        "report_id": report_id,
        "pcap_filename": pcap_filename,  # Store filename for reference
        "date_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "traffic_analysis": results,
        "attack_classification": attacks,
        "is_malicious": is_malicious
    }
    ReportManager.save_report(report_id, report_data)

    # Redirect to the generated report page
    return redirect(url_for("reports.get_report", report_id=report_id))


### Report Viewing ###
@reports_bp.route("/report/<report_id>")
def get_report(report_id):
    """Retrieves and displays a report based on its report_id."""
    reports = ReportManager.load_reports()
    report_data = reports.get(report_id)

    return render_template("report.html", report=report_data, report_id=report_id)
