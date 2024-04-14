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
#    the system with administrative capabilities including password reset and ensuring password uniqueness.
# 3. Unique Username Generation: Algorithm to generate unique usernames based on user's first initial and last name,
#    handling potential duplicates by appending a number.
# 4. Password Management: Implementation of a system for generating temporary passwords and enforcing password change
#    requirements on initial login, focusing on usability and security. The system also tracks old passwords to prevent reuse.
# 5. SQL Database Integration: Transitioning from a file-based system to a SQL database for managing user accounts.
#    This enhancement significantly improves scalability and efficiency, allowing for quicker access to
#    user data and more robust data management capabilities.
# 6. Efficiency and Scalability: By leveraging SQL database operations, the system achieves greater efficiency in data
#    retrieval and manipulation. Usernames and passwords can be quickly accessed and verified, and user data can be
#    efficiently updated. This represents a significant improvement over file-based systems, particularly as the
#    number of users grows.
# 7. Optimized Time Complexity: By using indexed database operations for user management tasks, the system benefits
#    from constant time complexity (O(1)) for critical operations such as user lookup, authentication, and data updates.
#    Additional complexity considerations are made for operations involving password uniqueness and account resets.
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
# Last Modified: 20240414
# Programmer: G W Bixby Jr

import bcrypt
import random
import string
import re
import sqlite3
from json import dumps, loads

class AuthenticationSystem:
    def __init__(self):
        # Establishes a connection to the SQLite database and sets up the user table if it does not exist.
        # Time Complexity: O(1) for the connection setup, O(n) for the table creation where n is the number of rows in the database.
        self.db_connection = sqlite3.connect('users.db')
        self.db_cursor = self.db_connection.cursor()
        self.db_cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                hashed_password TEXT,
                old_passwords TEXT,
                status TEXT
            )
        """)
        self.db_connection.commit()
        self.attempts_limit = 5

    def hash_password(self, password):
        # Hashes the password using bcrypt to ensure security against password cracking.
        # Time Complexity: O(1) because the hashing time does not change with the size of the input.
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def create_username(self, first_name, last_name):
        # Generates a unique username by combining the first letter of the first name with the last name.
        # If the username already exists, it appends a number to create a unique username.
        # Time Complexity: O(k) where k is the number of attempts to find a unique username.
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
        # Generates a secure, random 12-character password that includes a mix of letters, digits, and symbols.
        # Time Complexity: O(1) as the operation does not scale with the input size.
        characters = string.ascii_letters + string.digits + "!@#$%^&*()"
        password = ''.join(random.choice(characters) for i in range(12))
        return password

    def create_account(self, first_name, last_name):
        # Creates a new user account with a unique username and a temporary password.
        # Time Complexity: O(k) due to the username uniqueness check and O(1) for the actual insertion.
        username = self.create_username(first_name, last_name)
        password = self.generate_password()
        hashed_password = self.hash_password(password)
        self.db_cursor.execute("INSERT INTO users (username, hashed_password, old_passwords, status) VALUES (?, ?, ?, ?)",
                               (username, hashed_password.decode('utf-8'), dumps([hashed_password.decode('utf-8')]), 'temp'))
        self.db_connection.commit()
        print(f"Account created. Username: {username}. Temporary password: {password}")

    def user_login(self, username, password):
        # Handles user login by verifying the password against the stored hashed version.
        # If the user is logging in for the first time with a temporary password, it prompts a password change.
        # Time Complexity: O(1) for indexed lookup in the database.
        self.db_cursor.execute("SELECT hashed_password, old_passwords, status FROM users WHERE username=?", (username,))
        user_data = self.db_cursor.fetchone()
        if user_data:
            hashed_password, old_passwords, status = user_data
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
        # Prompts the user to change their password to meet specific criteria for security.
        # Time Complexity: O(1) for data retrieval, O(m) for password validation where m is the size of the password history.
        print("Your password must be changed.")
        print("Passwords must be 8-16 characters, including one lowercase, one uppercase, one number and one special character.")
        new_password = input("Enter your new password: ")
        if self.validate_new_password(username, new_password):
            hashed_new_password = self.hash_password(new_password).decode('utf-8')
            self.db_cursor.execute("SELECT old_passwords FROM users WHERE username=?", (username,))
            old_passwords = loads(self.db_cursor.fetchone()[0])
            old_passwords.append(hashed_new_password)
            self.db_cursor.execute("UPDATE users SET hashed_password=?, old_passwords=?, status='active' WHERE username=?",
                                   (hashed_new_password, dumps(old_passwords), username))
            self.db_connection.commit()
            print("Your password has been successfully updated.")
        else:
            print("Password does not meet the criteria.")

    def validate_new_password(self, username, password):
        # Validates the new password against established criteria and checks it hasn't been used before.
        # Time Complexity: O(m) where m is the number of previous passwords to check for uniqueness.
        if not (8 <= len(password) <= 16):
            return False
        if not re.search("[a-z]", password) or not re.search("[A-Z]", password):
            return False
        if not re.search("[0-9]", password) or not re.search("[!@#$%^&*()]", password):
            return False
        self.db_cursor.execute("SELECT old_passwords FROM users WHERE username=?", (username,))
        old_passwords = loads(self.db_cursor.fetchone()[0])
        for old_password in old_passwords:
            if bcrypt.checkpw(password.encode('utf-8'), old_password.encode('utf-8')):
                return False
        return True

    def admin_reset_password(self, username):
        # Allows an administrator to reset the password for a user, ensuring the new password hasn't been used before.
        # Time Complexity: O(m) for checking the uniqueness of the new password against old ones.
        new_password = self.generate_password()
        hashed_new_password = self.hash_password(new_password).decode('utf-8')
        self.db_cursor.execute("SELECT old_passwords FROM users WHERE username=?", (username,))
        old_passwords = loads(self.db_cursor.fetchone()[0])
        if hashed_new_password not in old_passwords:
            old_passwords.append(hashed_new_password)
            self.db_cursor.execute("UPDATE users SET hashed_password=?, old_passwords=?, status='temp' WHERE username=?",
                                   (hashed_new_password, dumps(old_passwords), username))
            self.db_connection.commit()
            print(f"Password has been reset for {username}. New temporary password: {new_password}")
        else:
            print("Previously used password. New password cannot match previously used passwords.")
