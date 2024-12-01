import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

load_dotenv()

def load_key(password: bytes, salt: bytes, length=32):
    kdf = Scrypt(salt=salt, length=length, n=2 ** 14, r=8, p=1, backend=default_backend())
    key = kdf.derive(password)
    return key


def decrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        iv = file.read(16)  # The first 16 bytes are the IV
        encrypted_data = file.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding after decryption
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    # Write decrypted data back to file
    with open(file_path, 'wb') as file:
        file.write(data)


def decrypt_folder(folder_path, password):
    # Load salt
    salt_file_path = os.path.join(folder_path, 'salt.bin')
    with open(salt_file_path, 'rb') as salt_file:
        salt = salt_file.read()

    # Derive the key
    key = load_key(password.encode(), salt)

    # Decrypt all files in the folder
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_name != 'salt.bin':  # Skip the salt file itself
                decrypt_file(file_path, key)
                print(f"Decrypted {file_path}")




# Usage
folder_path = os.getenv("FOLDER_PATH")
password = os.getenv("PASSWORD")
decrypt_folder(folder_path, password)
