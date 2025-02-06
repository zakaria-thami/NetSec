import os
from flask import Flask, request, redirect, render_template, send_from_directory, jsonify, url_for, session
import json
import bcrypt #to encrypt passwords
from flask_cors import CORS
from dotenv import load_dotenv
from routes import analyze_bp  # Import API routes

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key='myKey' #bad example for a security concept app 
CORS(app)  # Enable CORS for frontend communication

with open('credentials.json', 'r') as f:
    credentials = json.load(f)


# Register the API Blueprint
app.register_blueprint(analyze_bp, url_prefix="/api")

@app.route("/home")
def home():
    """Serve the main home page"""
    return render_template("home.html")  # Make sure the file is in the 'templates' folder

@app.route("/authenticate",methods=['POST'])
def authenticate():
    username = request.form['username']
    password = request.form['password'].encode('utf-8')
        # Check if username exists in credentials
    if username in credentials:
        # Get the stored hashed password
        hashed_password = credentials[username].encode('utf-8')

        # Verify the password
        if bcrypt.checkpw(password, hashed_password):
            # Password is correct, start a session
            session['username'] = username
            return redirect('/home')
        else:
            # Password is incorrect
            return "Invalid username or password", 401
    else:
        # Username not found
        return "Invalid username or password", 401

@app.route("/devices")
def devices():
    """Serve the display of discovered devices."""
    return render_template("devices.html")  # Make sure the file is in the 'templates' folder


@app.route("/reports")
def reports():
    """Serve the display of previous reports."""
    return render_template("reports.html")  # Make sure the file is in the 'templates' folder


@app.route("/")
def login():
    """Serve the login page."""
    return render_template("login.html")  # Make sure the file is in the 'templates' folder


@app.route("/static/<path:filename>")
def serve_static(filename):
    """Serve static files like CSS, JS, and images."""
    return send_from_directory("static", filename)

if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", 4000))
    app.run(debug=True, host="0.0.0.0", port=port)
