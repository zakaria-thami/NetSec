import json
import os

REPORTS_FILE = "reports.json"

class ReportManager:
    """Handles loading, saving, and retrieving reports."""
    
    @staticmethod
    def load_reports():
        """Loads existing reports from the JSON file."""
        if not os.path.exists(REPORTS_FILE):
            return {}

        try:
            with open(REPORTS_FILE, "r") as file:
                return json.load(file)
        except json.JSONDecodeError:
            return {}  # Return an empty dictionary if JSON is corrupted

    @staticmethod
    def save_report(report_id, data):
        """Saves a new report to the JSON file."""
        reports = ReportManager.load_reports()
        reports[report_id] = data
        with open(REPORTS_FILE, "w") as file:
            json.dump(reports, file, indent=4)