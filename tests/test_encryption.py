import unittest
import os
import json
from encrypt import generate_and_save_keys
from decrypt import add_secret, decrypt_value

class TestEncryption(unittest.TestCase):
    """Test suite for encryption and decryption functionality.
    
    This class tests the key generation, secret addition, and secret retrieval
    functionality of the encryption system.
    """

    def setUp(self):
        """Initialize test environment before each test.
        
        Creates a test file name that will be used across all tests.
        """
        self.test_file = "test_encrypted.json"
    
    def tearDown(self):
        """Clean up test environment after each test.
        
        Removes all test-related files (encrypted data and key files) from the filesystem.
        Files removed:
            - test_encrypted.json
            - private_key.pem
            - public_key.pem
        """
        files_to_remove = [
            self.test_file,
            "private_key.pem",
            "public_key.pem"
        ]
        for file in files_to_remove:
            try:
                os.remove(file)
            except FileNotFoundError:
                pass

    def test_key_generation(self):
        """Test RSA key pair generation and storage.
        
        Verifies that both private and public key files are created
        when generate_and_save_keys() is called.
        """
        generate_and_save_keys()
        self.assertTrue(os.path.exists("private_key.pem"))
        self.assertTrue(os.path.exists("public_key.pem"))

    def test_add_and_retrieve_secret(self):
        """Test the full encryption and decryption cycle.
        
        Tests:
            1. Adding a secret value with encryption
            2. Retrieving and decrypting the stored secret
            
        Verifies that the decrypted value matches the original input.
        """
        test_name = "test_key"
        test_value = "test_value"
        
        # Add secret and verify success message
        result = add_secret(self.test_file, test_name, test_value)
        self.assertEqual(result, "Secret added successfully")
        
        # Retrieve and decrypt secret, verify it matches original value
        retrieved = decrypt_value(self.test_file, test_name)
        self.assertEqual(retrieved, test_value)

if __name__ == '__main__':
    unittest.main()