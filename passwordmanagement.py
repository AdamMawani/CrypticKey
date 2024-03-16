import re

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
    
    user_credentials[username] = password
    return "Registration successful. You can now login."

def login(username, password):
    if username not in user_credentials:
        return "Username not found. Please register first."
    
    if user_credentials[username] != password:
        return "Incorrect password. Please try again."
    
    return "Login successful."

def main():
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ")
        
        if choice == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            print(register(username, password))
        
        elif choice == "2":
            username = input("Enter username: ")
            password = input("Enter password: ")
            print(login(username, password))
        
        elif choice == "3":
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please enter a valid option.")

if __name__ == "__main__":
    main()
