import json  # Import json for reading and writing JSON data
import os  # Import os for interacting with the file system

REPORTS_FILE = "reports.json"  # Define the filename where reports are stored

class ReportManager:
    """Handles loading, saving, and retrieving reports."""
    
    @staticmethod
    def load_reports():
        """Loads existing reports from the JSON file."""
        if not os.path.exists(REPORTS_FILE):  # If the reports file doesn't exist, return an empty dictionary
            return {}

        try:
            # Try to open and read the JSON file containing reports
            with open(REPORTS_FILE, "r") as file:
                return json.load(file)  # Return the parsed JSON data (reports)
        except json.JSONDecodeError:
            # If there is an error decoding the JSON (corrupted file), return an empty dictionary
            return {}

    @staticmethod
    def save_report(report_id, data):
        """Saves a new report to the JSON file."""
        reports = ReportManager.load_reports()  # Load existing reports
        reports[report_id] = data  # Add the new report using the provided report_id and data

        # Open the reports file and save the updated reports list as JSON
        with open(REPORTS_FILE, "w") as file:
            json.dump(reports, file, indent=4)  # Write the reports back to the file with proper indentation
