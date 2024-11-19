"""
Secure data decryption module using hybrid encryption (RSA + AES-GCM).

This module provides functionality to decrypt sensitive data that has been encrypted
using a combination of symmetric (AES) and asymmetric (RSA) encryption. The data
is stored in a JSON file along with necessary cryptographic components.

Requirements:
    - cryptography library
    - A valid private key file (private_key.pem)
    - An encrypted JSON file containing the encrypted data and metadata
"""

import json
import os
import base64
from getpass import getpass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

def decrypt_data(encrypted_file, password=None):
    """
    Decrypt the entire encrypted JSON file.
    
    Args:
        encrypted_file (str): Path to the encrypted JSON file
        password (str, optional): Password for decryption. If not provided, will prompt.
    
    Returns:
        list: Decrypted data as a list of dictionaries
    
    Raises:
        FileNotFoundError: If encrypted file or private key is missing
        ValueError: If decryption fails
    """
    with open(encrypted_file, "r") as f:
        encrypted_data = json.load(f)
    
    # Decode base64 components
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    tag = base64.b64decode(encrypted_data["tag"])
    encrypted_symmetric_key = base64.b64decode(encrypted_data["encrypted_key"])
    salt = base64.b64decode(encrypted_data["salt"])
    iv = base64.b64decode(encrypted_data["iv"])

    # Get password if not provided
    if password is None:
        password = getpass("Enter decryption password: ").encode()
    else:
        password = password.encode()

    # Derive symmetric key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    symmetric_key = kdf.derive(password)

    # Load private key
    try:
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        raise FileNotFoundError("Error: Private key not found")

    # Decrypt symmetric key
    try:
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception:
        raise ValueError("Error: Failed to decrypt symmetric key. Wrong password?")

    # Decrypt data
    try:
        cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        pt = decryptor.update(ciphertext) + decryptor.finalize()
        return json.loads(pt.decode())
    except Exception:
        raise ValueError("Error: Failed to decrypt data")

def decrypt_value(encrypted_file, name):
    """
    Retrieve a specific secret value by its name.
    
    Args:
        encrypted_file (str): Path to the encrypted JSON file
        name (str): Name of the secret to retrieve
    
    Returns:
        str: The secret value or error message
    """
    try:
        data = decrypt_data(encrypted_file)
        for item in data:
            if item['name'] == name:
                return item['value']
        return "Name not found"
    except Exception as e:
        return str(e)

def add_secret(encrypted_file, name, value):
    """
    Add a new secret to the encrypted file.
    
    Args:
        encrypted_file (str): Path to the encrypted JSON file
        name (str): Name for the new secret
        value (str): Value of the new secret
    
    Returns:
        str: Success or error message
    """
    try:
        # Get password
        password = getpass("Enter encryption password: ")
        
        # Decrypt existing data
        try:
            current_data = decrypt_data(encrypted_file, password)
        except FileNotFoundError:
            current_data = []

        # Check for duplicate names
        for item in current_data:
            if item['name'] == name:
                return "Error: Secret with this name already exists"

        # Add new secret
        current_data.append({"name": name, "value": value})

        # Re-encrypt with same password
        temp_file = "temp_input.json"
        try:
            # Save to temporary file
            with open(temp_file, "w") as f:
                json.dump(current_data, f)

            # Import encrypt function and re-encrypt
            from encrypt import encrypt_data
            encrypt_data(temp_file, encrypted_file)
            return "Secret added successfully"
        finally:
            # Clean up temp file
            try:
                os.remove(temp_file)
            except:
                pass

    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  To retrieve a secret: python decrypt.py get <name>")
        print("  To add a secret: python decrypt.py add <name> <value>")
        sys.exit(1)

    command = sys.argv[1]
    
    if command == "get":
        if len(sys.argv) != 3:
            print("Usage: python decrypt.py get <name>")
            sys.exit(1)
        result = decrypt_value("encrypted.json", sys.argv[2])
        print(result)
    
    elif command == "add":
        if len(sys.argv) != 4:
            print("Usage: python decrypt.py add <name> <value>")
            sys.exit(1)
        result = add_secret("encrypted.json", sys.argv[2], sys.argv[3])
        print(result)
    
    else:
        print("Unknown command. Use 'get' or 'add'")


