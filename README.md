# CrypticKey

CrypticKey is a simple user authentication system built with Flask, a lightweight Python web framework, to handle user registration and login securely. The system integrates the bcrypt library for password hashing, ensuring that user passwords are securely stored in the database.

## Features
- **User Registration**: Allows users to register by providing a username and password.
- **Password Hashing**: User passwords are securely hashed using bcrypt before being stored in the database.
- **User Login**: Validates user credentials during the login process, ensuring secure authentication.

## Installation
1. Clone the repository: `git clone <repository-url>`
2. Install dependencies: `pip install -r requirements.txt`

## Usage
1. Run the Flask application: `python app.py`
2. Access the application endpoints:
   - **Registration endpoint**: `POST /register`
     - Payload: `{ "username": "<username>", "password": "<password>" }`
   - **Login endpoint**: `POST /login`
     - Payload: `{ "username": "<username>", "password": "<password>" }`