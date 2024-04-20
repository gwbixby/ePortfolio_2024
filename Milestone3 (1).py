# Python Authentication System with bcrypt hashing and Enhanced Features
#
# Overview:
# This Python script is an enhanced version of a basic authentication system. Initially translated from Java,
# it incorporates significant improvements including secure password hashing with bcrypt, admin functionalities,
# unique username generation, and advanced password management. The intent is to demonstrate the application of
# secure coding practices, problem-solving skills in software design, and user management functionalities within
# an authentication system context.
#
# Key Enhancements:
# 1. Security Enhancement: Transition from MD5 to bcrypt for password hashing to address vulnerabilities and
#    enhance security.
# 2. Admin Functionality: Admin login feature to manage user accounts, demonstrating the ability to extend
#    the system with administrative capabilities.
# 3. Unique Username Generation: Algorithm to generate unique usernames based on user's first initial and last name,
#    handling potential duplicates by appending a number.
# 4. Password Management: Implementation of a system for generating temporary passwords and enforcing password change
#    requirements on initial login, focusing on usability and security.
#
# Date of Creation: 20240322
# Last Modified: 20240325
# Programmer: G W Bixby Jr


import bcrypt
import random
import string
import re  # For validating password criteria

class AuthenticationSystem:
    def __init__(self):
        # The file where user credentials are stored.
        self.credentials_file = "credentials.txt"
        # Maximum allowed failed login attempts before an account is locked.
        self.attempts_limit = 5
        # Password for the administrative account, hashed for security.
        self.admin_password = bcrypt.hashpw(b"adminpassword", bcrypt.gensalt())
        # Set to keep track of locked accounts to prevent login after too many failed attempts.
        self.locked_accounts = set()

    def hash_password(self, password):
        # Uses bcrypt to securely hash a given password. Ensures passwords are stored securely.
        # bcrypt hashing has a cost factor making the trade-off computationally expense for security.
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def check_password(self, hashed_password, user_password):
        # Compares a user-provided password with the hashed version to verify login attempts.
        # # Time Complexity: O(1) for the operation, but actual execution time depends on bcrypt's cost factor O(c).
        return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

    def create_username(self, first_name, last_name):
        # Generates a unique username from the user's name. Uses the first initial and up to the first 9 letters of the last name.
        # If a duplicate is found, increments a counter until a unique username is found.
        # Time complexity: O(n) due to linear search through all usernames, where n is the number of usernames
        # Time complexity will move to O(1) once database functionality is added
        base_username = (first_name[0] + last_name)[:10].lower()
        username = base_username
        counter = 1
        with open(self.credentials_file, 'r') as file:
            lines = file.readlines()
            usernames = [line.split('\t')[0] for line in lines]
            while username in usernames:
                username = f"{base_username}{counter}"
                counter += 1
        return username

    def generate_password(self):
        # Generates a secure 12-character password that meets specified criteria, ensuring strong passwords for new accounts.
        # Time Complexity: O(1), as the operation does not scale with the number of users.
        characters = string.ascii_letters + string.digits + "!@#$%^&*()"
        password = ''.join(random.choice(characters) for i in range(12))
        return password

    def create_account(self, first_name, last_name):
        # Creates a new user account with a unique username and a secure, temporary password. Marks the password as temporary.
        # Time Complexity: O(n) for the username generation process. Moves to O(1) once DB is created
        username = self.create_username(first_name, last_name)
        password = self.generate_password()
        hashed_password = self.hash_password(password)
        with open(self.credentials_file, 'a') as file:
            file.write(f"{username}\t{hashed_password.decode('utf-8')}\ttemp\n")
        print(f"Account created. Username: {username}. Temporary password: {password}")

    def user_login(self, username, password):
        # Handles user login attempts. Locks accounts after 5 failed attempts and prompts for a password change if necessary.
        # Time Complexity: O(n) due to linear search through user records. Moves to O(1) once DB is created
        if username in self.locked_accounts:
            print("This account is locked.")
            return False

        attempts = 0
        while attempts < self.attempts_limit:
            with open(self.credentials_file, 'r') as file:
                for line in file:
                    user, hashed_password, status = line.strip().split('\t')
                    if user == username and self.check_password(hashed_password, password):
                        print("Login successful.")
                        if status == "temp":
                            self.prompt_password_change(username)
                        return True
                    else:
                        attempts += 1
                        print("Invalid password. Please try again.")
                        break  # Exits the for-loop after the first password check fails, avoiding unnecessary checks.
            
            if attempts == self.attempts_limit:
                print("Account locked due to too many failed attempts.")
                self.locked_accounts.add(username)
                # In Milestone 4, I will build out a SQL database to manage account status.
                # Placeholder for logic to mark account 'locked' in SQL database
                return False
        return False

    def prompt_password_change(self, username):
        # Prompts the user to change their password if it's marked as temporary.
        # Time Complexity: O(n) due to linear search and update of user record. Moves to nearly O(1) in DB functionality
        print("Your password must be changed.")
        print("(Must be 8-16 characters, include one uppercase, one lowercase, one number and one special character)")
        new_password = input("Enter your new password: ")
        if self.validate_new_password(new_password):
            hashed_new_password = self.hash_password(new_password).decode('utf-8')
            self.update_password(username, hashed_new_password)
            print("Your password has been successfully updated.")
        else:
            print("Password must match specified criteria.")

    def validate_new_password(self, password):
        # Validates the new password against specified criteria.
        # Time Complexity: O(1) for the checks performed, but actual complexity depends on the length of the password O(l).
        if not (8 <= len(password) <= 16):
            return False
        if not re.search("[a-z]", password) or not re.search("[A-Z]", password):
            return False
        if not re.search("[0-9]", password) or not re.search("[!@#$%^&*()]", password):
            return False
       
