import bcrypt
import json

def hash_password(password):
    # Encode the password to bytes and hash it using bcrypt
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')  # Decode to string for JSON storage

if __name__ == '__main__':
    # Input username and password
    password = input("Enter password: ")
    print(hash_password(password))