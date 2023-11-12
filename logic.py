from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import json


class PasswordManager:
    def __init__(self, file_path="encrypted_passwords.json"):
        self.file_path = file_path
        self.key = None
        self.valid_master_pwd = False
        self.passwords = {}

    def generate_key(self, master_password):
        # Use PBKDF2 with SHA-256 for key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,  # adjust as needed for your security requirements
            salt=b"some_salt",  # a unique salt for each user
            length=32,  # the length of the derived key
        )
        key = kdf.derive(master_password.encode())
        self.key = base64.urlsafe_b64encode(key)

    def load_passwords(self):
        try:
            with open(self.file_path, "rb") as file:
                data = file.read()
                if self.key:
                    try:
                        cipher_suite = Fernet(self.key)
                        decrypted_data = cipher_suite.decrypt(data)
                        self.passwords = json.loads(decrypted_data.decode())
                        self.valid_master_pwd = True
                    except:
                        print("Invalid master password. Please try again.")
                        self.valid_master_pwd = False
                else:
                    print(
                        "Master password not set. Please set a master password first."
                    )
        except FileNotFoundError:
            # If the file doesn't exist, initialize an empty dictionary
            self.passwords = {}
            self.valid_master_pwd = True

    def save_passwords(self):
        if self.key:
            cipher_suite = Fernet(self.key)
            encrypted_data = cipher_suite.encrypt(json.dumps(self.passwords).encode())
            with open(self.file_path, "wb") as file:
                file.write(encrypted_data)
        else:
            print("Master password not set. Please set a master password first.")

    def set_master_password(self, master_password):
        self.generate_key(master_password)
        self.load_passwords()
        print("Master password set successfully!")

    def add_password(self, service, username, password):
        self.passwords[service] = {"username": username, "password": password}
        self.save_passwords()

    def get_password(self, service):
        if service in self.passwords:
            return self.passwords[service]["password"]
        else:
            return None

    def list_services(self):
        return list(self.passwords.keys())


def main():
    manager = PasswordManager()

    while True:
        print("\nPassword Manager Menu:")
        print("1. Set Master Password")
        print("2. Add Password")
        print("3. Get Password")
        print("4. List Services")
        print("5. Exit")

        choice = input("Enter your choice (1-5): ")

        if choice == "1":
            master_password = input("Enter your master password: ")
            manager.set_master_password(master_password)

        elif choice == "2":
            service = input("Enter the service: ")
            username = input("Enter the username: ")
            password = input("Enter the password: ")
            manager.add_password(service, username, password)
            print("Password added successfully!")

        elif choice == "3":
            service = input("Enter the service to retrieve the password: ")
            stored_password = manager.get_password(service)
            if stored_password:
                print(f"Password for {service}: {stored_password}")
            else:
                print(f"No password found for {service}")

        elif choice == "4":
            services = manager.list_services()
            if services:
                print("List of services:")
                for service in services:
                    print(f"- {service}")
            else:
                print("No services found.")

        elif choice == "5":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please enter a number between 1 and 5.")


if __name__ == "__main__":
    main()