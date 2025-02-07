import bcrypt
import json

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()  # Convert bytes to string before storing

def add_user(username, password):
    hashed_password = hash_password(password)

    try:
        with open("credentials.json", "r") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {"users": []}

    data["users"].append({"username": username, "password": hashed_password})

    with open("credentials.json", "w") as file:
        json.dump(data, file, indent=4)

    print(f"User {username} added successfully!")

if __name__ == "__main__":
    user = input("Enter username: ")
    pwd = input("Enter password: ")
    add_user(user, pwd)
