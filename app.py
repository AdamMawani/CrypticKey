import os
import re
import uuid
import smtplib
import logging
import secrets
from datetime import timedelta
from flask import Flask, request, jsonify, session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
from flasgger import Swagger

load_dotenv()

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = os.getenv('SECRET_KEY', str(uuid.uuid4()))

# Set up rate limiting
limiter = Limiter(app, key_func=get_remote_address)

# Configure session timeout
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Configure email
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
EMAIL_SMTP_SERVER = os.getenv('EMAIL_SMTP_SERVER')
EMAIL_SMTP_PORT = int(os.getenv('EMAIL_SMTP_PORT'))

# Configure URL serializer for email verification and password reset
serializer = URLSafeTimedSerializer(app.secret_key)

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Set up logging
logging.basicConfig(level=logging.INFO)

# Swagger setup
swagger = Swagger(app)

# User model
class User(db.Model):
    username = db.Column(db.String(80), primary_key=True)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    verified = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(200), nullable=True)
    role = db.Column(db.String(10), default='user')  # 'user' or 'admin'

db.create_all()

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
    if User.query.filter_by(username=username).first():
        return "Username already exists. Please choose another username."

    if User.query.filter_by(email=email).first():
        return "Email already registered. Please use another email address."

    if not check_password_strength(password):
        return "Password does not meet the criteria for strength."

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    verification_token = serializer.dumps(email, salt='email-confirm')
    verification_url = f"http://127.0.0.1:5000/verify-email/{verification_token}"
    send_email(email, 'Verify your email', f'Please verify your email by clicking on the link: {verification_url}')

    user = User(username=username, password=hashed_password, email=email)
    db.session.add(user)
    db.session.commit()
    return "Registration successful. A verification email has been sent."

# Email verification function
@app.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user:
            user.verified = True
            db.session.commit()
            return jsonify({'message': 'Email verified successfully.'})
        else:
            return jsonify({'message': 'User not found.'}), 400
    except Exception as e:
        logging.error(f"Error verifying email: {e}")
        return jsonify({'message': 'Verification link is invalid or has expired.'}), 400

# User login function
@limiter.limit("5 per minute")  # Limit login attempts to prevent brute force attacks
def login(username, password):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "Username not found. Please register first."

    if not bcrypt.check_password_hash(user.password, password):
        return "Incorrect password. Please try again."

    if not user.verified:
        return "Email not verified. Please check your email."

    session['username'] = username
    session.permanent = True  # Enable session timeout
    return "Login successful."

# Password change function
def change_password(username, old_password, new_password):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "Username not found."

    if not bcrypt.check_password_hash(user.password, old_password):
        return "Incorrect old password."

    if not check_password_strength(new_password):
        return "New password does not meet the criteria for strength."

    new_hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = new_hashed_password
    db.session.commit()
    return "Password changed successfully."

# Logout function
def logout():
    session.clear()
    return "Logged out successfully."

# Password reset request function
def request_password_reset(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        return "Email not found. Please register first."

    reset_token = serializer.dumps(email, salt='password-reset')
    reset_url = f"http://127.0.0.1:5000/reset-password/{reset_token}"
    send_email(email, 'Reset your password', f'Please reset your password by clicking on the link: {reset_url}')

    user.reset_token = reset_token
    db.session.commit()
    return "Password reset request received. Please check your email."

# Password reset function
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user:
            if request.method == 'POST':
                data = request.get_json()
                new_password = data.get('new_password')

                if not check_password_strength(new_password):
                    return jsonify({'message': 'New password does not meet the criteria for strength.'}), 400

                new_hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                user.password = new_hashed_password
                user.reset_token = None
                db.session.commit()
                return jsonify({'message': 'Password reset successfully.'})

            return '''
                <form method="POST">
                    <input type="password" name="new_password" placeholder="Enter new password">
                    <button type="submit">Reset Password</button>
                </form>
            '''
        else:
            return jsonify({'message': 'User not found.'}), 400
    except Exception as e:
        logging.error(f"Error resetting password: {e}")
        return jsonify({'message': 'Reset link is invalid or has expired.'}), 400

# Route for user registration
@app.route('/register', methods=['POST'])
def register_route():
    """
    Register a new user.
    ---
    parameters:
      - in: body
        name: body
        schema:
          type: object
          required:
            - username
            - password
            - email
          properties:
            username:
              type: string
            password:
              type: string
            email:
              type: string
    responses:
      200:
        description: Registration successful
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    response = register(username, password, email)
    return jsonify({'message': response})

# Route for user login
@app.route('/login', methods=['POST'])
def login_route():
    """
    Login a user.
    ---
    parameters:
      - in: body
        name: body
        schema:
          type: object
          required:
            - username
            - password
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      200:
        description: Login successful
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    response = login(username, password)
    return jsonify({'message': response})

# Route for changing password
@app.route('/change-password', methods=['POST'])
def change_password_route():
    """
    Change a user's password.
    ---
    parameters:
      - in: body
        name: body
        schema:
          type: object
          required:
            - username
            - old_password
            - new_password
          properties:
            username:
              type: string
            old_password:
              type: string
            new_password:
              type: string
    responses:
      200:
        description: Password changed successfully
    """
    data = request.get_json()
    username = data.get('username')
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    response = change_password(username, old_password, new_password)
    return jsonify({'message': response})

# Route for logging out
@app.route('/logout', methods=['GET'])
def logout_route():
    """
    Logout a user.
    ---
    responses:
      200:
        description: Logged out successfully
    """
    response = logout()
    return jsonify({'message': response})

# Route for password reset request
@app.route('/request-password-reset', methods=['POST'])
def request_password_reset_route():
    """
    Request a password reset.
    ---
    parameters:
      - in: body
        name: body
        schema:
          type: object
          required:
            - email
          properties:
            email:
              type: string
    responses:
      200:
        description: Password reset request received
    """
    data = request.get_json()
    email = data.get('email')
    response = request_password_reset(email)
    return jsonify({'message': response})

if __name__ == "__main__":
    app.run(debug=True)