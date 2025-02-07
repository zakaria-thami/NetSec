import bcrypt  # Import bcrypt for password hashing
import json  # Import json for storing user credentials

# Function to hash a password using bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()  # Generate a random salt
    hashed = bcrypt.hashpw(password.encode(), salt)  # Hash the password with the salt
    return hashed.decode()  # Convert bytes to string before storing

# Function to add a new user to the credentials file
def add_user(username, password):
    hashed_password = hash_password(password)  # Hash the given password

    try:
        # Try to open and load existing user data from credentials.json
        with open("credentials.json", "r") as file:
            data = json.load(file)  # Load JSON data
    except (FileNotFoundError, json.JSONDecodeError):
        # If file doesn't exist or has invalid JSON, initialize with an empty user list
        data = {"users": []}

    # Append the new user's credentials to the list
    data["users"].append({"username": username, "password": hashed_password})

    # Save the updated data back to credentials.json
    with open("credentials.json", "w") as file:
        json.dump(data, file, indent=4)  # Write JSON data with indentation for readability

    print(f"User {username} added successfully!")  # Confirmation message

# Main execution block to get user input and add the user
if __name__ == "__main__":
    user = input("Enter username: ")  # Prompt for username
    pwd = input("Enter password: ")  # Prompt for password
    add_user(user, pwd)  # Call the function to store user credentials
