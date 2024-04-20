import bcrypt
import getpass

class AuthenticationSystem:
    def __init__(self):
        self.credentials_file = "credentials.txt"
        self.attempts_limit = 5
        self.admin_password = bcrypt.hashpw(b"adminPassword", bcrypt.gensalt())

    def hash_password(self, password):
        # Upgraded password security from MD5 hash to bcrypt with salting
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def check_password(self, hashed_password, user_password):
        return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

    def create_username(self, first_name, last_name):
        # Usernames will be created by input from user of first and last name
        base_username = (first_name[0] + last_name)[:10].lower()
        username = base_username
        # Duplicate usernames will be appended by sequential numbering (e.g., jsmith, jsmith2, etc)
        counter = 1
        with open(self.credentials_file, 'r') as file:
            lines = file.readlines()
            usernames = [line.split('\t')[0] for line in lines]
            while username in usernames:
                username = f"{base_username}{counter}"
                counter += 1
        return username

    def create_account(self, first_name, last_name):
        # Account creation of the username and a temporary password
        username = self.create_username(first_name, last_name)
        password = self.generate_password()
        hashed_password = self.hash_password(password)
        with open(self.credentials_file, 'a') as file:
            file.write(f"{username}\t{hashed_password.decode('utf-8')}\n")
        print(f"Account created. Username: {username}. Temporary password: {password}")

    def generate_password(self):
        # Placeholder
        # As I build my algorithms and data structures this is where I will generate a generic login password
        #This will be for initial login, and then users will be required to create their own password after initial login.
        return "genericPassword"

    def admin_login(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.admin_password)

    def user_login(self, username, password):
        attempts = 0
        while attempts < self.attempts_limit:
            with open(self.credentials_file, 'r') as file:
                for line in file:
                    user, hashed_password = line.strip().split('\t')
                    if user == username and self.check_password(hashed_password, password):
                        print("Login successful")
                        # After initial login, user will be required to change their password with one they create
                        # The password will be required to have 8-16 characters, one uppercase, one lowercase, 
                        # and one special character
                        return True
                attempts += 1
                print("Invalid username/password. Please try again.")
                if attempts == self.attempts_limit:
                    print("Account locked due to too many failed attempts.")
                    # This is where the code will go to lock out the user
                    # Admin will be able to unlock accounts
                    return False
        return False

    # Logging function for login attempts
    def log_attempt(self, username, success):
        # This is where code will go to log login attempts and successes
        pass