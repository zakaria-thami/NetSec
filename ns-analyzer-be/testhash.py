import bcrypt
import json

CREDENTIALS_FILE = "credentials.json"

def load_credentials():
    """Load user credentials from JSON file."""
    try:
        with open(CREDENTIALS_FILE, "r") as file:
            data = json.load(file)
        return data.get("users", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def debug_check_login(username, password):
    """Check username and password while printing debug information."""
    users = load_credentials()
    print("Loaded users:", users)  # Debug: print all loaded users

    for user in users:
        print(f"\nChecking username: {user['username']}")
        if user["username"] == username:
            stored_hash = user["password"]
            print(f"Stored Hash: {stored_hash}")  # Debug: print stored hash
            
            # Verify password
            if bcrypt.checkpw(password.encode(), stored_hash.encode()):
                print("✅ Password matches!")
                return "Login successful!"
            else:
                print("❌ Password does NOT match!")

    return "Invalid username or password."

# Run the test
if __name__ == "__main__":
    username = input("Enter username: ")
    password = input("Enter password: ")

    result = debug_check_login(username, password)
    print("\nResult:", result)
