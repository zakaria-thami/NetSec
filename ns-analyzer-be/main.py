# backend/app.py
import os
from flask import Flask, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend communication

@app.route('/')
def home():
    return jsonify({"message": "Hello from Flask API!"})

if __name__ == '__main__':
    port = int(os.getenv("FLASK_PORT", 4000))  # Default to 5000 if not set
    app.run(debug=True, host='0.0.0.0', port=port)