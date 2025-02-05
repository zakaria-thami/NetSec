# backend/app.py
import os
from flask import Flask, render_template
from flask_cors import CORS
from dotenv import load_dotenv
from routes import analyze_bp  # Import the Blueprint from routes.py

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend communication

# Register Blueprint from routes.py
app.register_blueprint(analyze_bp, url_prefix='/api')

@app.route('/')
def home():
    return render_template("Home.html")

if __name__ == '__main__':
    port = int(os.getenv("FLASK_PORT", 4000))  # Default to 4000 if not set
    app.run(debug=True, host='0.0.0.0', port=port)
