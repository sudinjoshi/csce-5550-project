import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import secrets

# Load environment variables from a .env file
load_dotenv()

# Function to generate an encryption key using the Scrypt key derivation function
def generate_key(password: bytes, salt: bytes, length=32):
    try:
        # Create a Scrypt key derivation function with the specified parameters
        kdf = Scrypt(salt=salt, length=length, n=2 ** 14, r=8, p=1, backend=default_backend())

        # Derive the key using the provided password
        key = kdf.derive(password)
        return key
    except Exception as e:
        # Catch and print any errors that occur during key generation
        print(f"Error generating key: {e}")
        return None

# Function to encrypt a single file using AES (Advanced Encryption Standard)
def encrypt_file(file_path, key):
    try:
        # Open the file in binary read mode and read the contents
        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Generate a random 16-byte initialization vector (IV) for the AES encryption
        iv = secrets.token_bytes(16)

        # Set up the AES cipher in CBC mode with the provided key and IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad the file data to ensure its size is a multiple of the AES block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(file_data) + padder.finalize()

        # Encrypt the padded data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Open the file in binary write mode and overwrite it with the IV + encrypted data
        with open(file_path, 'wb') as file:
            file.write(iv + encrypted_data)  # Prefix the IV to the encrypted data for later decryption

        print(f"Encrypted {file_path}")
    except Exception as e:
        # Catch and print any errors that occur during the encryption of the file
        print(f"Error encrypting file {file_path}: {e}")

# Function to encrypt all files in a folder
def encrypt_folder(folder_path, password):
    try:
        # Generate a random salt to use for key derivation (this salt will be saved for later decryption)
        salt = secrets.token_bytes(16)

        # Generate the encryption key using the password and salt
        key = generate_key(password.encode(), salt)

        if key is None:
            print("Error: Key generation failed. Exiting.")
            return

        # Walk through the folder, including subdirectories, to find all files
        for root, _, files in os.walk(folder_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)  # Get the full path to the file
                encrypt_file(file_path, key)  # Encrypt the file using the generated key

        # Save the salt to a file in the folder, so it can be used for decryption later
        with open(os.path.join(folder_path, 'salt.bin'), 'wb') as salt_file:
            salt_file.write(salt)
        print(f"Salt saved at {os.path.join(folder_path, 'salt.bin')}")
    except Exception as e:
        # Catch and print any errors that occur during the encryption of the folder
        print(f"Error encrypting folder {folder_path}: {e}")

# Usage example: Encrypt all files in the folder specified by the environment variables
folder_path = os.getenv("FOLDER_PATH")  # Retrieve the folder path from environment variables
password = "introductiontocomputersecuritycourse"  # Retrieve the password from environment variables

# Check if both the folder path and password are available
if folder_path and password:
    encrypt_folder(folder_path, password)  # Encrypt the folder if both parameters are available
else:
    print("Error: Folder path or password not provided.")  # Print an error message if any parameter is missing
