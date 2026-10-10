# Cryptographic Encryption Vault

## Project Overview
Cryptographic Encryption Vault is a Python-based project that encrypts and decrypts files and directories using AES-256-GCM authenticated encryption.

## Features
- AES-256-GCM encryption and authentication.
- Master passphrase-based key derivation using Scrypt.
- Random salt and nonce for encryption.
- Recursive processing of directory files.
- Separate output folders for encrypted and restored files.
- Prevents overwriting existing destination files.
- File integrity verification using SHA-256 hashes.

## Technologies Used
- Python
- Cryptography library
- AES-256-GCM
- Scrypt
- PowerShell

## Installation
Install Python, then install the required dependency:

```bash
python -m pip install -r requirements.txt
```

## Usage

### Encrypt a directory
```bash
python crypto_vault.py encrypt test_data encrypted_vault
```

### Decrypt a directory
```bash
python crypto_vault.py decrypt encrypted_vault restored_data
```

The same master passphrase must be used for decryption.

## Testing
The project was tested using sample text files. Encryption and decryption outputs were checked, and SHA-256 hashes were compared to verify that restored files matched the originals.

## Screenshots
Execution screenshots are stored in the `screenshots/` directory.

## Security Notes
- Keep the master passphrase secure.
- Do not overwrite or delete original files until restoration has been verified.
- This is an educational project and has not been audited for production use.
- Secure key backup and recovery are not implemented in the current version.
