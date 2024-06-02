import re
import uuid
from flask import Flask, request, jsonify, session
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = str(uuid.uuid4())  # Ensure secret key is set for session handling

# In-memory user data storage
user_credentials = {}
user_emails = {}

# Password strength checking function
def check_password_strength(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*()_+{}|:"<>?`\-=[\];\',./]', password):
        return False
    return True

# User registration function
def register(username, password, email):
    if username in user_credentials:
        return "Username already exists. Please choose another username."
    
    if email in user_emails.values():
        return "Email already registered. Please use another email address."

    if not check_password_strength(password):
        return "Password does not meet the criteria for strength."
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user_credentials[username] = hashed_password
    user_emails[username] = email
    return "Registration successful. You can now login."

# User login function
def login(username, password):
    if username not in user_credentials:
        return "Username not found. Please register first."
    
    hashed_password = user_credentials[username]
    if not bcrypt.check_password_hash(hashed_password, password):
        return "Incorrect password. Please try again."
    
    session['username'] = username
    return "Login successful."

# Password change function
def change_password(username, old_password, new_password):
    if username not in user_credentials:
        return "Username not found."
    
    hashed_password = user_credentials[username]
    if not bcrypt.check_password_hash(hashed_password, old_password):
        return "Incorrect old password."
    
    if not check_password_strength(new_password):
        return "New password does not meet the criteria for strength."
    
    new_hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user_credentials[username] = new_hashed_password
    return "Password changed successfully."

# Logout function
def logout():
    session.clear()
    return "Logged out successfully."

# Password reset request function (stub)
def request_password_reset(email):
    if email not in user_emails.values():
        return "Email not found. Please register first."
    # Implement the email sending functionality here
    return "Password reset request received. (Functionality not implemented)"

# Route for user registration
@app.route('/register', methods=['POST'])
def register_route():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    response = register(username, password, email)
    return jsonify({'message': response})

# Route for user login
@app.route('/login', methods=['POST'])
def login_route():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    response = login(username, password)
    return jsonify({'message': response})

# Route for changing password
@app.route('/change-password', methods=['POST'])
def change_password_route():
    data = request.get_json()
    username = data.get('username')
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    response = change_password(username, old_password, new_password)
    return jsonify({'message': response})

# Route for logging out
@app.route('/logout', methods=['GET'])
def logout_route():
    response = logout()
    return jsonify({'message': response})

# Route for password reset request
@app.route('/request-password-reset', methods=['POST'])
def request_password_reset_route():
    data = request.get_json()
    email = data.get('email')
    response = request_password_reset(email)
    return jsonify({'message': response})

if __name__ == "__main__":
    app.run(debug=True)