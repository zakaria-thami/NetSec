import os  # Import os module for environment variable handling
from flask import Flask, render_template, send_from_directory, session  # Import necessary Flask components
import json  # Import json for reading credentials
from flask_cors import CORS  # Import CORS for cross-origin resource sharing
from dotenv import load_dotenv  # Import dotenv for loading environment variables from a .env file
from routes import analyze_bp, reports_bp, auth_bp  # Import the Blueprints for routing
from models.report_manager import ReportManager  # Import ReportManager class for handling reports
from models.device_manager import DeviceManager, scan_network  # Import DeviceManager and network scan utility
from network_info import get_network_info  # Import the network info utility

# Load environment variables from .env file
load_dotenv()

# Initialize Flask application
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = "test123"  # Set the secret key for session management
CORS(app)  # Enable Cross-Origin Resource Sharing (CORS) for the application

# Read credentials from the 'credentials.json' file
with open('credentials.json', 'r') as f:
    credentials = json.load(f)

# Register the API Blueprints
app.register_blueprint(analyze_bp, url_prefix="/api")  # Blueprint for analysis API
app.register_blueprint(reports_bp, url_prefix="/api")  # Blueprint for reports API
app.register_blueprint(auth_bp, url_prefix='/auth')  # Blueprint for authentication API

@app.route("/")  # Define route for login page
def login():
    """Serve the login page."""
    return render_template("login.html")  # Render the login page

    return render_template('home.html')  # Render the home page if logged in (Unreachable code, likely a bug)

@app.route("/home")  # Define route for home page
def home():
    if 'username' not in session:  # Check if the user is logged in
        return render_template("login.html")  # Redirect to login if not logged in

    # Get network information for the home page
    network_data = get_network_info()
    return render_template("home.html", network=network_data)  # Render the home page with network data

@app.route("/devices")  # Define route for devices page
def devices():
    if 'username' not in session:  # Check if the user is logged in
        return render_template("login.html")  # Redirect to login if not logged in

    """Serve the display of discovered devices."""
    devices_data = scan_network()  # Scan the network for devices
    
    return render_template("devices.html", devices=devices_data)  # Render the devices page with device data

@app.route("/history")  # Define route for the reports history page
def reports():
    if 'username' not in session:  # Check if the user is logged in
        return render_template("login.html")  # Redirect to login if not logged in

    """Renders the reports page with metadata from saved reports."""
    reports_data = ReportManager.load_reports()  # Load the saved reports
    reports_list = []  # Initialize the list for report data

    for report_id, data in reports_data.items():
        # Extract report metadata and prepare data for display
        date_time = data.get("date_time", "Unknown")
        packet_count = sum(data.get("traffic_analysis", {}).get("protocol_counts", {}).values())
        is_malicious = data.get("is_malicious", False)
        flag = "Hostile" if is_malicious else "Benign"

        reports_list.append({
            "report_id": report_id,
            "report_name": f"Report {report_id[:8]}",  # Display a short version of the report ID
            "date_time": date_time,
            "packet_count": packet_count,
            "flag": flag
        })

    return render_template("history.html", reports=reports_list)  # Render the history page with reports

@app.route("/static/<path:filename>")  # Define route for serving static files (CSS, JS, images)
def serve_static(filename):
    """Serve static files like CSS, JS, and images."""
    return send_from_directory("static", filename)  # Send the requested static file from the 'static' directory

# Main block to run the Flask application
if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", 4000))  # Get the port from environment variables, default to 4000
    app.run(debug=True, host="0.0.0.0", port=port)  # Run the application with debug mode enabled and available on all network interfaces
