# AES-My-File

Encrypt and decrypt your files using the AES-256-GCM algorithm.

## Features

- 🔐 Uses AES-256-GCM encryption algorithm, providing strong security
- 📁 Supports file selection via native system dialogs
- 🔑 PBKDF2-based key derivation (using HMAC-SHA256)
- 🎯 Supports chunked encryption/decryption for large files
- 🖥️ Cross-platform support: Windows, macOS, Linux

## Requirements

- [Zig](https://ziglang.org/) 0.11.0

## Build and Run

```bash
zig build run
```

## Build Executable

```bash
zig build
```

The generated executable is located at `zig-out/bin/aes-my-file`

## Usage

1. Run the program, and a system file selection dialog will appear.
2. Select the file to encrypt or decrypt:
   - Normal file: Selecting it will perform encryption, generating a `.enc` file.
   - `.enc` file: Selecting it will perform decryption, generating a `.dec` file.
3. Enter a password (at least 5 characters).
4. Confirm the password when encrypting.
5. Wait for the process to complete.

## Technical Details

### Encryption Algorithm
- **Encryption Method**: AES-256-GCM (Galois/Counter Mode)
- **Key Derivation**: PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP recommended)
- **Salt**: Independent 16-byte random salt per file
- **Key Length**: 256 bits
- **Nonce**: Independent random nonce for each encryption block

### File Format
Encrypted file format:
```
[16 bytes Salt][Block1: 16-byte Tag + 12-byte Nonce + Ciphertext][Block2: Tag + Nonce + Ciphertext]...
```

### File Dialog
Uses the [Native File Dialog](https://github.com/mlabbe/nativefiledialog) library to provide a native system file selection experience.

## Notes

⚠️ **Security Recommendations**:
- Please use a strong password (recommended at least 12 characters, including uppercase and lowercase letters, numbers, and special characters).
- Keep your password safe; lost passwords mean files cannot be decrypted.
- It is recommended to delete the original file only after the encrypted file has been successfully decrypted and verified.

## License

MIT
