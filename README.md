# Cryptodo

[![PyPI version](https://badge.fury.io/py/cryptodo.svg)](https://badge.fury.io/py/cryptodo)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

Cryptodo is a comprehensive Python library for text encryption, decryption, and cryptographic operations. It provides over 20 different encryption methods ranging from classical ciphers to modern cryptographic techniques, making it perfect for learning cryptography, educational purposes, and securing data.

## 📚 Features

### 🔐 Classical Ciphers
- **Caesar Cipher (V1)** - Classic shift cipher with fixed modulo 26
- **Substitution Cipher** - Key-based monoalphabetic substitution
- **Vigenère Cipher (V5)** - Polyalphabetic cipher with case preservation
- **Autokey Cipher (V18)** - Vigenère variant with no repeating period
- **Playfair Cipher (V12)** - Digraph substitution cipher (WWII era)
- **Hill Cipher (V13)** - Matrix-based linear algebra cipher (1929)
- **ADFGVX Cipher (V14)** - WWI German Army field cipher with transposition

### 🔄 Modern & Advanced Ciphers
- **XOR Cipher (V4)** - Repeating key XOR with Base64 encoding
- **Chaos Cipher (V17)** - Logistic map keystream generator
- **Deep Vault (V11)** - Multi-layer obfuscation with 7 different transforms
- **Atbash Cipher (V7)** - Keyed alphabet reversal with rotation
- **Numeric Shift (V3)** - Digit-level encryption with rail fence option

### 🎨 Creative Encodings
- **Emoji Cipher (V10)** - Map letters to emojis for fun messages
- **DNA Encoding (V16)** - 2-bit to nucleotide base mapping
- **Braille Cipher (V20)** - Keyed Braille pattern encoding
- **Mnemonic Cipher (V21)** - BIP39-style word pair encoding
- **Morse Code (V8)** - Dots and dashes encoding

### 🛡️ Security & Steganography
- **Zero-Width Steganography (V15)** - Hide messages in invisible characters
- **Homophonic Cipher (V19)** - Flatten frequency analysis with multiple codes
- **RSA-lite (V9)** - Educational public-key cryptography
- **Hash Functions (V6)** - SHA256 and MD5 checksums
- **File Encryption (FileCrypto)** - Base64 and XOR file operations

### 🔑 Key Generation
- **KeyGenerator** - Generate random keys, passwords, and numeric keys
- **KeyVariable** - Predefined character sets for various use cases

## 📦 Installation

```bash
pip install cryptodo
```

## 🚀 Quick Start

### Basic Encryption Example

```python
from cryptodo import Crypto, KeyGenerator

# Caesar cipher encryption
cipher = Crypto("Hello World!", 3)
encrypted_text = cipher.encrypt()
print(f"Encrypted: {encrypted_text}")

# Decryption
decipher = Crypto(encrypted_text, 3)
decrypted_text = decipher.decrypt()
print(f"Decrypted: {decrypted_text}")
```

### Advanced Cipher Examples

```python
from cryptodo import (
    CryptoV2, CryptoV4XOR, CryptoV5Vigenere, 
    CryptoV11DeepVault, CryptoV15ZeroWidth,
    CryptoV21Mnemonic, KeyGenerator
)

# Vigenère cipher
vigenere = CryptoV5Vigenere("Hello, World!", "lemon")
encrypted = vigenere.encrypt()
decrypted = CryptoV5Vigenere(encrypted, "lemon").decrypt()

# XOR cipher with Base64
xor_cipher = CryptoV4XOR("Secret message", "my-secret-key")
encrypted = xor_cipher.encrypt()
decrypted = CryptoV4XOR(encrypted, "my-secret-key").decrypt()

# Deep Vault - Multi-layer obfuscation
vault = CryptoV11DeepVault("master-key", layers=12)
blob = vault.encode("Top secret data")
print(f"Layer sequence: {vault.describe()}")
restored = CryptoV11DeepVault("master-key", layers=12).decode(blob)

# Zero-width steganography
stego = CryptoV15ZeroWidth(
    secret="Hidden message",
    key="optional-key",
    cover_text="This is normal text"
)
hidden = stego.hide()
revealed = CryptoV15ZeroWidth(cover_text=hidden, key="optional-key").reveal()

# Mnemonic cipher (BIP39-style)
mnemonic = CryptoV21Mnemonic("Hello", "key")
words = mnemonic.encrypt()
restored = CryptoV21Mnemonic(words, "key").decrypt()
```

### File Encryption

```python
from cryptodo import FileCrypto

# XOR encrypt a file
fc = FileCrypto("document.pdf", key="file-key")
encrypted_path = fc.xor_encrypt_file()
decrypted_path = FileCrypto(encrypted_path, key="file-key").xor_decrypt_file()

# Base64 encode a file
b64_path = fc.base64_encode_file()
decoded_path = FileCrypto(b64_path).base64_decode_file()

# Get file checksum
checksum = fc.sha256_checksum()
```

## 📖 Complete Cipher Guide

| Class | Method | Description | Key Type |
|-------|--------|-------------|----------|
| `Crypto` | `encrypt()`/`decrypt()` | Caesar cipher with shift | Integer (0-25) |
| `Crypto` | `substitution_encrypt()`/`decrypt()` | Keyed substitution cipher | Integer (seed) |
| `CryptoV2` | `encrypt()`/`decrypt()` | Keyed alphabet substitution | String key |
| `CryptoV2` | `caesar_variation_encrypt()`/`decrypt()` | Byte-wise Unicode shift | Integer |
| `CryptoV3Num` | `encrypt()`/`decrypt()` | Digit-level numeric cipher | Integer (shift) |
| `CryptoV3Num` | `rail_fence_encrypt()`/`decrypt()` | Rail fence transposition | Integer (rails) |
| `CryptoV4XOR` | `encrypt()`/`decrypt()` | XOR cipher with Base64 | String key |
| `CryptoV5Vigenere` | `encrypt()`/`decrypt()` | Classic Vigenère cipher | Alphabetic string |
| `CryptoV6Hash` | `sha256()`/`md5()` | Hash functions | None |
| `CryptoV7Atbash` | `encrypt()`/`decrypt()` | Keyed Atbash cipher | Integer (rotation) |
| `CryptoV8Morse` | `encrypt()`/`decrypt()` | Morse code encoding | None |
| `CryptoV9RSAlite` | `encrypt()`/`decrypt()` | Educational RSA | (e,n)/(d,n) |
| `CryptoV10Emoji` | `encrypt()`/`decrypt()` | Emoji substitution | Integer (seed) |
| `CryptoV11DeepVault` | `encode()`/`decode()` | Multi-layer obfuscation | String key |
| `CryptoV12Playfair` | `encrypt()`/`decrypt()` | Classic Playfair cipher | String key |
| `CryptoV13Hill` | `encrypt()`/`decrypt()` | Hill matrix cipher | 2x2 matrix |
| `CryptoV14ADFGVX` | `encrypt()`/`decrypt()` | WWI ADFGVX cipher | Two string keys |
| `CryptoV15ZeroWidth` | `hide()`/`reveal()` | Zero-width steganography | Optional string |
| `CryptoV16DNA` | `encrypt()`/`decrypt()` | DNA nucleotide encoding | String key |
| `CryptoV17Chaos` | `encrypt()`/`decrypt()` | Chaotic keystream | String key |
| `CryptoV18Autokey` | `encrypt()`/`decrypt()` | Autokey cipher | Alphabetic string |
| `CryptoV19Homophonic` | `encrypt()`/`decrypt()` | Homophonic substitution | Integer (seed) |
| `CryptoV20Braille` | `encrypt()`/`decrypt()` | Braille pattern encoding | String key |
| `CryptoV21Mnemonic` | `encrypt()`/`decrypt()` | BIP39-style word pairs | String key |
| `FileCrypto` | `xor_encrypt_file()`/`decrypt()` | File XOR encryption | String key |
| `FileCrypto` | `base64_encode_file()`/`decode()` | File Base64 encoding | None |

## 🔐 Security Note

Cryptodo is designed for **educational purposes**, learning cryptography, and data obfuscation. While many ciphers are historically significant and fun to use, they should NOT be relied upon for securing sensitive data in production environments. For real security needs, use well-audited libraries like:
- `cryptography` (Fernet, AES-GCM)
- `PyNaCl` (libsodium)
- `ssl`/`tls` for network security

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Contact & Support

- **Author**: K.A. Ishan Oshada
- **Email**: ic31908@gmail.com
- **GitHub**: [@ishanoshada](https://github.com/ishanoshada)

## 🙏 Acknowledgments

- Inspired by classical cryptography texts
- Educational ciphers based on historical algorithms
- Built with Python's standard library for maximum compatibility