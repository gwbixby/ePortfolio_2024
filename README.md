# Python Authentication System

## Overview

This Python Authentication System enhances security and scalability in user management by integrating advanced technologies such as bcrypt for secure password hashing and SQLite for robust database management. Designed for applications requiring reliable user authentication, this system includes features like unique username generation, secure password management, and mandatory password changes for new users, making it ideal for both small and large-scale projects.

## Features

*Secure Password Hashing*: Utilizes bcrypt to encrypt passwords, enhancing security against brute-force attacks.

*SQL Database Integration*: Leverages an SQLite database for efficient user account management.

*Unique Username Generation*: Automatically generates unique usernames by appending numbers to prevent duplicates.

*Temporary Passwords*: Issues temporary passwords for new account setups with a mandatory password change on first login.

*Admin Functionality*: Allows administrators to reset passwords and manage user accounts, ensuring system integrity and security.

## Dependencies

**Python 3.x**: Ensure you have Python 3.x installed on your system.

**bcrypt**: Used for hashing and verifying passwords.

**sqlite3**: Manages interactions with the SQLite database.

**re (Regular Expressions)**: Validates password strength and criteria.

## Usage

### Creating a New User Account

Call the **create_account** method with the user's first name and last name to generate a unique username and temporary password.

### Logging In

Use the **user_login** method with the username and password to authenticate users. New users will be prompted to change their password upon their first login.

### Admin Functions

Administrators can reset user passwords using the **admin_reset_password** method to ensure continued security compliance.

### Contributing

Contributions to the Python Authentication System are welcome! Please fork the repository, make your changes, and submit a pull request for review.

### Security

This system implements several security measures; however, we recommend conducting a security audit when integrating it into production environments to ensure it meets all security requirements.
