"""
A module for secure file encryption using hybrid encryption (RSA + AES-GCM).
This implementation combines symmetric encryption for data and asymmetric encryption
for key protection, providing both security and efficiency.
"""

import json
import os
import base64
from getpass import getpass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

def generate_and_save_keys():
    """
    Generate and save RSA key pair for asymmetric encryption.
    
    Generates a 2048-bit RSA key pair and saves both private and public keys
    to PEM files in the current directory.
    
    Returns:
        RSAPrivateKey: The generated private key object
    
    Files created:
        - private_key.pem: The private RSA key in PKCS8 format
        - public_key.pem: The public RSA key
    """
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Save private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    with open("public_key.pem", "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    return private_key

def encrypt_data(input_file, output_file):
    """
    Encrypt a JSON file using hybrid encryption (AES-GCM + RSA).
    
    This function performs the following steps:
    1. Generates a symmetric key using password-based key derivation (PBKDF2)
    2. Encrypts the input JSON data using AES-GCM
    3. Protects the symmetric key using RSA encryption
    4. Saves all encrypted data and metadata in a structured JSON format
    
    Args:
        input_file (str): Path to the input JSON file to encrypt
        output_file (str): Path where the encrypted data will be saved
    
    The output JSON structure contains:
        - ciphertext: The encrypted data (base64 encoded)
        - tag: The GCM authentication tag (base64 encoded)
        - encrypted_key: The RSA-encrypted symmetric key (base64 encoded)
        - salt: The salt used for key derivation (base64 encoded)
        - iv: The initialization vector (IV) used for AES-GCM (base64 encoded)
    
    Note:
        - The input file will be deleted after successful encryption
        - If RSA keys don't exist, they will be automatically generated
        - The encryption password is securely prompted from the user
    
    Raises:
        json.JSONDecodeError: If the input file is not valid JSON
        FileNotFoundError: If the input file doesn't exist
        PermissionError: If there are file permission issues
    """
    # Get password securely
    password = getpass("Enter encryption password: ").encode()
    
    # Generate salt
    salt = os.urandom(16)
    
    # Derive symmetric key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    symmetric_key = kdf.derive(password)
    
    # Load JSON data
    with open(input_file, "r") as f:
        data = json.load(f)
    
    # Generate a random 96-bit (12 byte) IV for GCM mode
    iv = os.urandom(12)
    
    # Encrypt JSON data with AES-GCM
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    
    # Get authentication tag
    ciphertext = encryptor.update(json.dumps(data).encode()) + encryptor.finalize()
    tag = encryptor.tag
    
    # Load or generate RSA keys
    try:
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        private_key = generate_and_save_keys()
    
    # Encrypt symmetric key
    public_key = private_key.public_key()
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Create structured output
    encrypted_data = {
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "encrypted_key": base64.b64encode(encrypted_symmetric_key).decode('utf-8'),
        "salt": base64.b64encode(salt).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8')
    }
    
    # Save encrypted data as JSON
    with open(output_file, "w") as f:
        json.dump(encrypted_data, f, indent=4)
    
    # Delete the input file
    os.remove(input_file)

if __name__ == "__main__":
    encrypt_data("input.json", "encrypted.json")
