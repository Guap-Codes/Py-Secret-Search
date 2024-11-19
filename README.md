# Py-Secret-Search

A secure command-line secret management system using hybrid encryption (RSA + AES-GCM) to safely store and retrieve sensitive information.

## Features

- Hybrid encryption using RSA and AES-GCM for maximum security
- Command-line interface for easy secret management
- Secure password-based key derivation (PBKDF2)
- Support for storing multiple secrets with name-value pairs
- Automatic key generation and management

## Requirements

- Python 3.6+
- cryptography library

## Installation

1. Clone the repository:

```git clone https://github.com/Guap-Codes/Py-Secret-Search.git```

```cd py-secret-search```

2. Install required packages:

```bash
pip install cryptography
```

## Usage

### First-time Setup

The first time you use the system, it will automatically generate RSA key pairs:
- `private_key.pem`: Keep this secure and never share it
- `public_key.pem`: Used for encryption

### Initial Encryption

1. Create an `input.json` file with your secrets in the following format:

```json
[
    {
        "name": "api_key",
        "value": "1234567890abcdef"
    },
    {
        "name": "database_password",
        "value": "mysecretpassword"
    }
]
```

2. Run the encryption:

```bash
python encrypt.py
```

This will:
- Prompt for an encryption password
- Encrypt your `input.json` file
- Save the encrypted data as `encrypted.json`
- Securely delete the `input.json` file

### Managing Secrets

Once your secrets are encrypted, use `decrypt.py` to manage them:

To retrieve a secret:
```bash
python decrypt.py get <secret_name>
```

Example:
```bash
python decrypt.py get api_key
```

To add a new secret:
```bash
python decrypt.py add <secret_name> <secret_value>
```

Example:
```bash
python decrypt.py add new_api_key "abcdef123456"
```

## Security Features

- **Hybrid Encryption**: Uses RSA for key encryption and AES-GCM for data encryption
- **Secure Key Derivation**: Implements PBKDF2 with SHA256
- **Authentication**: AES-GCM provides authenticated encryption
- **Secure Storage**: All sensitive data is encrypted at rest
- **Clean-up**: Temporary files are automatically removed after operations

## File Structure

- `encrypt.py`: Handles encryption operations and key generation
- `decrypt.py`: Manages decryption and secret retrieval/addition
- `encrypted.json`: Stores the encrypted secrets (created automatically)
- `private_key.pem`: RSA private key (generated on first use)
- `public_key.pem`: RSA public key (generated on first use)
- `tests/`: Directory containing test files
  - `__init__.py`: Makes the tests directory a Python package
  - `test_encryption.py`: Tests for encryption/decryption functionality

## Testing

To run the tests:

```bash
# From the project root directory
python -m unittest discover tests
```

The test suite includes:
- Key generation tests
- Secret addition and retrieval tests
- Error handling tests

For developers contributing to the project, please ensure:
- All tests pass before submitting pull requests
- New features include corresponding test cases
- Test coverage remains high

## Best Practices

1. Keep your `private_key.pem` secure and backed up
2. Use strong passwords for encryption
3. Never share your encryption password
4. Regularly backup your `encrypted.json` file

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Notice

While this tool implements strong encryption practices, please ensure you follow your organization's security policies when storing sensitive information.


