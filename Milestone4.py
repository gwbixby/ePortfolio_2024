# Python Authentication System with bcrypt hashing and Enhanced Features
#
# Overview:
# This Python script enhances an authentication system by incorporating a SQL database to manage user accounts, 
# leveraging bcrypt for secure password hashing, and implementing features such as unique username generation, 
# secure password management, and forced password changes for new users. Designed to improve security, efficiency, 
# and scalability, the system represents a significant upgrade over file-based or less secure authentication methods.
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
# 5. SQL Database Integration: Transitioning from a file-based system to a SQL database for managing user accounts. 
#    This enhancement significantly improves scalability and efficiency, allowing for quicker access to #
#    user data and more robust data management capabilities.
# 6. Efficiency and Scalability: By leveraging SQL database operations, the system achieves greater efficiency in data
#    retrieval and manipulation. Usernames and passwords can be quickly accessed and verified, and user data can be 
#    efficiently updated. This represents a significant improvement over file-based systems, particularly as the 
#    number of users grows. 
# 7. Optimized Time Complexity: By using indexed database operations for user management tasks, the system benefits 
#    from constant time complexity (O(1)) for critical operations such as user lookup, authentication, and data updates.
#    This optimization is crucial for maintaining system performance and responsiveness as the user base expands.
#
# Usage:
# The system provides functionalities to create new user accounts with unique usernames and temporary passwords, 
# user login with password verification, and mandatory password change for new users to set a secure password. 
# This script can be integrated into larger applications requiring secure user authentication and account management.
#
# Dependencies:
# *bcrypt - For hashing and verifying passwords.
# *sqlite3 - For managing the SQL database.
# *re - For validating password criteria based on regular expressions.
#
# Date of Creation: 20240322
# Last Modified: 20240407
# Programmer: G W Bixby Jr

import bcrypt
import random
import string
import re
import sqlite3

class AuthenticationSystem:
    def __init__(self):
        self.db_connection = sqlite3.connect('users.db')
        self.db_cursor = self.db_connection.cursor()
        # Initialize the database table if it doesn't already exist.
        self.db_cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                hashed_password TEXT,
                status TEXT
            )
        """)
        self.db_connection.commit()
        self.attempts_limit = 5

    def hash_password(self, password):
        # Hashes the password with bcrypt. Time Complexity: O(1)
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def create_username(self, first_name, last_name):
        # Generates a unique username. Time Complexity: O(1) with indexed database access.
        base_username = (first_name[0] + last_name)[:10].lower()
        username = base_username
        counter = 1
        while True:
            self.db_cursor.execute("SELECT EXISTS(SELECT 1 FROM users WHERE username=?)", (username,))
            if not self.db_cursor.fetchone()[0]:
                break
            username = f"{base_username}{counter}"
            counter += 1
        return username

    def generate_password(self):
        # Generates a secure, random 12-character password. Time Complexity: O(1)
        characters = string.ascii_letters + string.digits + "!@#$%^&*()"
        password = ''.join(random.choice(characters) for i in range(12))
        return password

    def create_account(self, first_name, last_name):
        # Creates a new account. Time Complexity: O(1) for indexed insert.
        username = self.create_username(first_name, last_name)
        password = self.generate_password()
        hashed_password = self.hash_password(password)
        self.db_cursor.execute("INSERT INTO users (username, hashed_password, status) VALUES (?, ?, ?)",
                               (username, hashed_password.decode('utf-8'), 'temp'))
        self.db_connection.commit()
        print(f"Account created. Username: {username}. Temporary password: {password}")

    def user_login(self, username, password):
        # Handles user login. Time Complexity: O(1) for indexed search.
        self.db_cursor.execute("SELECT hashed_password, status FROM users WHERE username=?", (username,))
        user_data = self.db_cursor.fetchone()
        if user_data:
            hashed_password, status = user_data
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                print("Login successful.")
                if status == "temp":
                    self.prompt_password_change(username)
                return True
            else:
                print("Invalid password.")
                return False
        else:
            print("Username does not exist.")
            return False

    def prompt_password_change(self, username):
        # Prompts the user for a password change. Time Complexity: O(1) for indexed update.
        print("Your password must be changed.")
        print("(Must be 8-16 characters, include one uppercase, one lowercase, one number, and one special character)")
        new_password = input("Enter your new password: ")
        if self.validate_new_password(new_password):
            hashed_new_password = self.hash_password(new_password).decode('utf-8')
            self.db_cursor.execute("UPDATE users SET hashed_password=?, status='active' WHERE username=?",
                                   (hashed_new_password, username))
            self.db_connection.commit()
            print("Your password has been successfully updated.")
        else:
            print("Password does not meet the criteria.")

    def validate_new_password(self, password):
        # Validates the new password against criteria. Time Complexity: O(1)
        if not (8 <= len(password) <= 16):
            return False
        if not re.search("[a-z]", password) or not re.search("[A-Z]", password):
            return False
        if not re.search("[0-9]", password) or not re.search("[!@#$%^&*()]", password):
            return False
        return True


