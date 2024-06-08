import re
import uuid
import smtplib
import secrets
import sqlite3
from datetime import timedelta
from flask import Flask, request, jsonify, session
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = str(uuid.uuid4())  # Ensure secret key is set for session handling

# Set up rate limiting
limiter = Limiter(app, key_func=get_remote_address)

# Configure session timeout
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Configure email
EMAIL_USER = 'your-email@example.com'
EMAIL_PASSWORD = 'your-email-password'
EMAIL_SMTP_SERVER = 'smtp.example.com'
EMAIL_SMTP_PORT = 587

# Configure URL serializer for email verification and password reset
serializer = URLSafeTimedSerializer(app.secret_key)

# Set up SQLite database connection
conn = sqlite3.connect('users.db', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                email TEXT NOT NULL,
                verified INTEGER DEFAULT 0,
                reset_token TEXT)''')
conn.commit()

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

# Send email function
def send_email(to_email, subject, body):
    with smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        message = f'Subject: {subject}\n\n{body}'
        server.sendmail(EMAIL_USER, to_email, message)

# User registration function
def register(username, password, email):
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    if c.fetchone():
        return "Username already exists. Please choose another username."

    c.execute('SELECT * FROM users WHERE email = ?', (email,))
    if c.fetchone():
        return "Email already registered. Please use another email address."

    if not check_password_strength(password):
        return "Password does not meet the criteria for strength."

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    verification_token = serializer.dumps(email, salt='email-confirm')
    verification_url = f"http://127.0.0.1:5000/verify-email/{verification_token}"
    send_email(email, 'Verify your email', f'Please verify your email by clicking on the link: {verification_url}')

    c.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, hashed_password, email))
    conn.commit()
    return "Registration successful. A verification email has been sent."

# Email verification function
@app.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
        c.execute('UPDATE users SET verified = 1 WHERE email = ?', (email,))
        conn.commit()
        return jsonify({'message': 'Email verified successfully.'})
    except Exception as e:
        return jsonify({'message': 'Verification link is invalid or has expired.'}), 400

# User login function
@limiter.limit("5 per minute")  # Limit login attempts to prevent brute force attacks
def login(username, password):
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    if not user:
        return "Username not found. Please register first."

    if not bcrypt.check_password_hash(user[1], password):
        return "Incorrect password. Please try again."

    if user[3] == 0:
        return "Email not verified. Please check your email."

    session['username'] = username
    session.permanent = True  # Enable session timeout
    return "Login successful."

# Password change function
def change_password(username, old_password, new_password):
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    if not user:
        return "Username not found."

    if not bcrypt.check_password_hash(user[1], old_password):
        return "Incorrect old password."

    if not check_password_strength(new_password):
        return "New password does not meet the criteria for strength."

    new_hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    c.execute('UPDATE users SET password = ? WHERE username = ?', (new_hashed_password, username))
    conn.commit()
    return "Password changed successfully."

# Logout function
def logout():
    session.clear()
    return "Logged out successfully."

# Password reset request function
def request_password_reset(email):
    c.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = c.fetchone()
    if not user:
        return "Email not found. Please register first."

    reset_token = serializer.dumps(email, salt='password-reset')
    reset_url = f"http://127.0.0.1:5000/reset-password/{reset_token}"
    send_email(email, 'Reset your password', f'Please reset your password by clicking on the link: {reset_url}')

    c.execute('UPDATE users SET reset_token = ? WHERE email = ?', (reset_token, email))
    conn.commit()
    return "Password reset request received. Please check your email."

# Password reset function
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
        if request.method == 'POST':
            data = request.get_json()
            new_password = data.get('new_password')

            if not check_password_strength(new_password):
                return jsonify({'message': 'New password does not meet the criteria for strength.'}), 400

            new_hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            c.execute('UPDATE users SET password = ?, reset_token = NULL WHERE email = ?', (new_hashed_password, email))
            conn.commit()
            return jsonify({'message': 'Password reset successfully.'})

        return '''
            <form method="POST">
                <input type="password" name="new_password" placeholder="Enter new password">
                <button type="submit">Reset Password</button>
            </form>
        '''
    except Exception as e:
        return jsonify({'message': 'Reset link is invalid or has expired.'}), 400

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