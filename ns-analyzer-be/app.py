import os
from flask import Flask, render_template, send_from_directory, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from routes import analyze_bp  # Import API routes

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)  # Enable CORS for frontend communication

# Register the API Blueprint
app.register_blueprint(analyze_bp, url_prefix="/api")

@app.route("/")
def home():
    """Serve the main frontend HTML file."""
    return render_template("Home.html")  # Make sure the file is in the 'templates' folder

@app.route("/static/<path:filename>")
def serve_static(filename):
    """Serve static files like CSS, JS, and images."""
    return send_from_directory("static", filename)

if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", 4000))
    app.run(debug=True, host="0.0.0.0", port=port)
