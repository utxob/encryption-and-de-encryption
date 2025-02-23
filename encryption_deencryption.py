import os
import hashlib
import getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time

# Function to derive key from password using SHA-256 hashing
def derive_key(password: str) -> bytes:
    """Generate a 32-byte encryption key using SHA-256 hashing."""
    return hashlib.sha256(password.encode()).digest()

# Function for file encryption
def encrypt_file(input_file: str, password: str):
    """Encrypt the given file."""
    key = derive_key(password)
    cipher = AES.new(key, AES.MODE_CBC)
    
    try:
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        encrypted_file = input_file + ".enc"
        with open(encrypted_file, 'wb') as f:
            f.write(cipher.iv)  # Store IV at the beginning
            f.write(ciphertext)
        
        print(f" File encryption completed: {encrypted_file}")
    
    except FileNotFoundError:
        print(" File not found! Please provide a valid path.")

# Function for file decryption
def decrypt_file(encrypted_file: str, password: str):
    """Decrypt the given file."""
    key = derive_key(password)
    
    try:
        with open(encrypted_file, 'rb') as f:
            iv = f.read(16)  # First 16 bytes are IV
            ciphertext = f.read()
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        try:
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            decrypted_file = encrypted_file.replace(".enc", "")
            with open(decrypted_file, 'wb') as f:
                f.write(plaintext)
            
            print(f" File decryption completed: {decrypted_file}")
        
        except ValueError:
            print(" Incorrect password!")

    except FileNotFoundError:
        print(" File not found! Please provide a valid path.")

# Timer function for brute force protection
def brute_force_protection():
    """Prevent brute-force attempts with a delay after multiple incorrect attempts."""
    attempts = 0
    max_attempts = 10
    lock_time = 0
    
    while attempts < max_attempts:
        print(f"Attempts left: {max_attempts - attempts}")
        password = getpass.getpass("🔑 Enter password: ")
        
        if is_correct_password(password):  # Replace with your validation function
            return True
        else:
            print(" Incorrect password.")
            attempts += 1
        
        if attempts >= max_attempts:
            lock_time = 5 * 60  # 5 minutes lock
            print(f"💥 Too many failed attempts. Locking for {lock_time / 60} minutes.")
            time.sleep(lock_time)
    
    return False

def is_correct_password(password):
    # Add your password validation logic here
    return True  # For now, always true for example

# CLI menu
def main():
    """CLI menu (Runs in a loop until user exits)."""
    while True:
        print("\n🔐 File Encryption & Decryption Tool")
        print("1️ Encrypt a file")
        print("2️ Decrypt a file")
        print("3️ Exit")
        choice = input("👉 Select an option (1/2/3): ")

        if choice == '1':
            input_file = input("📂 Enter the full path of the file to encrypt: ")
            password = getpass.getpass("🔑 Enter password: ")
            encrypt_file(input_file, password)

        elif choice == '2':
            encrypted_file = input("📂 Enter the full path of the encrypted file: ")
            password = getpass.getpass("🔑 Enter password: ")
            decrypt_file(encrypted_file, password)

        elif choice == '3':
            print("👋 Exiting the tool. Goodbye!")
            break  # Exit the loop

        else:
            print("❌ Invalid option! Please try again.")

if __name__ == "__main__":
    main()
