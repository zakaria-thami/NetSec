# backend/routes.py
from flask import Blueprint, request, jsonify
from analyze_traffic import load_pcap, analyze_packets, classify_attacks

# Define Blueprint
analyze_bp = Blueprint("analyze", __name__)

@analyze_bp.route('/analyze', methods=['POST'])
def analyze():
    """REST API Endpoint to analyze a PCAP file."""
    data = request.get_json()
    filename = data.get("filename")

    if not filename:
        return jsonify({"error": "No filename provided."}), 400

    packets = load_pcap(filename)
    if isinstance(packets, dict) and "error" in packets:
        return jsonify(packets), 400

    results = analyze_packets(packets)
    attacks = classify_attacks(packets)

    return jsonify({
        "traffic_analysis": results,
        "attack_classification": attacks
    })
