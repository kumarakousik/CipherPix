# CipherPix 🔐
Secure end-to-end encrypted steganography tool for hiding messages in images

CipherPix combines military-grade encryption with advanced steganography to invisibly embed secret messages into images. Using password-protected LSB (Least Significant Bit) embedding and hybrid RSA+AES encryption, your messages remain undetectable and secure.

✨ Key Features

🔒 Hybrid Encryption: RSA-2048 + AES-256-CBC encryption

🎨 High-Quality LSB Steganography: PSNR >45 dB (imperceptible changes)

🔗 Linked List Architecture: CRC32 integrity checks on embedded data

🔑 Password-Protected Embedding: PBKDF2-HMAC-SHA256 key derivation

🤖 AI-Powered: VGG16-based optimal embedding location selection

🎯 Auto-Detection: Automatically detects LSB depth during extraction

🖼️ Quality Metrics: Real-time PSNR, SSIM, and visual difference analysis


🔐 Security Architecture

1) Alice (Sender) encrypts message with Bob's public key

2) Encrypted payload embedded using password-derived locations

3) Bob (Receiver) extracts with password + private key

4) End-to-end security: even with image access, data remains encrypted
