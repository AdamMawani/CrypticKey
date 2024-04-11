import re
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Dictionary to store user credentials
user_credentials = {}

def check_password_strength(password):
    # Check if password length is at least 8 characters
    if len(password) < 8:
        return False
    
    # Check if password contains at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False
    
    # Check if password contains at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False
    
    # Check if password contains at least one digit
    if not re.search(r'\d', password):
        return False
    
    # Check if password contains at least one special character
    if not re.search(r'[!@#$%^&*()_+{}|:"<>?`\-=[\];\',./]', password):
        return False
    
    return True

def register(username, password):
    if username in user_credentials:
        return "Username already exists. Please choose another username."
    
    if not check_password_strength(password):
        return "Password does not meet the criteria for strength."
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user_credentials[username] = hashed_password
    return "Registration successful. You can now login."

def login(username, password):
    if username not in user_credentials:
        return "Username not found. Please register first."
    
    hashed_password = user_credentials[username]
    if not bcrypt.check_password_hash(hashed_password, password):
        return "Incorrect password. Please try again."
    
    return "Login successful."

@app.route('/register', methods=['POST'])
def register_route():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    response = register(username, password)
    return jsonify({'message': response})

@app.route('/login', methods=['POST'])
def login_route():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    response = login(username, password)
    return jsonify({'message': response})

if __name__ == "__main__":
    app.run(debug=True)