# 🔒 Secure File Storage System

A Flask-based secure file storage system using **hybrid cryptography** (AES-256 + RSA-2048) for zero-knowledge file encryption.

## 🌟 Features

### ✅ Phase 2 (Current) - Hybrid Encryption Active
- **🔐 Military-grade encryption** - AES-256-CBC for files, RSA-2048 for keys
- **🔑 Automatic key generation** - RSA key pairs generated per user
- **🛡️ Zero-knowledge storage** - Server cannot decrypt user files
- **📁 Seamless experience** - Upload/download feels normal to users
- **🔒 Hybrid cryptography** - Fast AES encryption + secure RSA key protection
- **📊 File metadata tracking** - Secure storage of encrypted file information

### ⏳ Planned Features (Future Phases)
- **👥 User authentication** - Individual accounts with isolated storage
- **🤝 File sharing** - Share encrypted files between users
- **☁️ Cloud storage integration** - AWS S3 compatibility
- **📱 Modern UI** - React frontend with drag-and-drop
- **🔗 API endpoints** - RESTful API for third-party integrations

## 🏗️ System Architecture

### Hybrid Encryption Flow
```
Upload: File → AES-256 Encryption → RSA Key Protection → Secure Storage
Download: Encrypted Data → RSA Key Recovery → AES Decryption → Original File
```

### Security Model
- **Files**: Encrypted with unique AES-256 keys per file
- **Keys**: AES keys encrypted with user's RSA-2048 public key
- **Storage**: All data stored encrypted, server has no access to plaintext
- **Zero-knowledge**: Even system administrators cannot access user files

## 🚀 Quick Start

### Prerequisites
- Python 3.7+
- pip (Python package manager)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/secure-file-storage.git
   cd secure-file-storage
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Open your browser**
   ```
   http://localhost:5000
   ```

## 🛠️ Technology Stack

### Backend
- **Flask** - Web framework
- **pycryptodome** - Cryptographic operations
- **Python 3.9+** - Programming language

### Cryptography
- **AES-256-CBC** - File encryption
- **RSA-2048** - Key encryption  
- **PKCS#1 OAEP** - RSA padding
- **PKCS#7** - AES padding
- **Random IV** - Initialization vectors

### Storage
- **JSON files** - Key and metadata storage (Phase 2)
- **Local filesystem** - Encrypted file storage
- **Base64 encoding** - Binary data handling

## 📁 Project Structure

```
secure-file-storage/
├── app.py                    # Main Flask application
├── crypto_utils.py           # Cryptographic operations
├── key_storage.py            # RSA key management
├── file_storage.py           # File metadata management
├── requirements.txt          # Python dependencies
├── README.md                 # Project documentation
├── .gitignore               # Git ignore rules
├── templates/
│   ├── index_encrypted.html  # Main page with encryption status
│   ├── success_encrypted.html # Upload success page
│   └── keys.html            # Key viewing page (debug)
├── encrypted_uploads/        # Encrypted files storage
├── user_keys.json           # RSA key pairs (auto-generated)
└── file_metadata.json       # File metadata (auto-generated)
```

## 🔐 Security Features

### Encryption Details
- **File Encryption**: AES-256 in CBC mode with random IV
- **Key Encryption**: RSA-2048 with PKCS#1 OAEP padding
- **Key Generation**: Cryptographically secure random keys
- **Padding**: PKCS#7 for AES, OAEP for RSA

### Security Guarantees
- ✅ Files are **never stored in plaintext**
- ✅ Each file gets a **unique AES key**
- ✅ AES keys are **RSA-encrypted** before storage
- ✅ Server has **no access** to user data without private keys
- ✅ **Computationally infeasible** to break (2048-bit RSA)

### What Attackers See
```bash
# Encrypted file on disk
encrypted_uploads/enc_default_user_0.dat:
xJ2kL9mP3vQ8aBcDeFgH1iJkLmNoPqRsTuVwXyZ... (gibberish)

# Encrypted AES key in metadata
"encrypted_aes_key": "kM9nX2pL5qR8..." (RSA-encrypted)
```

## 🧪 Testing Your Installation

### 1. Basic Functionality Test
```bash
# Upload a file through the web interface
# Check that encrypted_uploads/ contains .dat files
# Download the file - should be identical to original
```

### 2. Encryption Verification
```bash
# Open any .dat file in encrypted_uploads/
# Content should be unreadable gibberish
# This proves encryption is working
```

### 3. Key Management Test
```bash
# Visit http://localhost:5000/keys
# Should show your RSA public and private keys
# Delete user_keys.json and restart
# New keys should be generated automatically
```

## 📊 Development Phases

### ✅ Phase 1: Basic File Storage (Completed)
- File upload/download functionality
- Basic Flask web interface
- Local file storage

### ✅ Phase 2: Hybrid Encryption (Current)
- AES-256 file encryption
- RSA-2048 key management
- Zero-knowledge architecture
- Enhanced UI with encryption status

### ⏳ Phase 3: User Management (Planned)
- User registration/login system
- Individual key pairs per user
- Session management
- User file isolation

### ⏳ Phase 4: Advanced Features (Planned)
- File sharing between users
- Cloud storage integration (AWS S3)
- RESTful API
- React frontend
- Mobile responsiveness

## 🔧 Configuration

### Environment Variables
```bash
# Flask configuration
FLASK_ENV=development          # development/production
SECRET_KEY=your-secret-key     # Change in production

# Encryption settings
RSA_KEY_SIZE=2048             # RSA key size in bits
AES_KEY_SIZE=32               # AES key size in bytes (256-bit)

# File upload limits
MAX_FILE_SIZE=16777216        # 16MB in bytes
ALLOWED_EXTENSIONS=txt,pdf,png,jpg,jpeg,gif,doc,docx
```

### Production Deployment
For production use:
- Change `SECRET_KEY` to a secure random value
- Use PostgreSQL instead of JSON files
- Enable HTTPS/TLS
- Use cloud storage (AWS S3) with encryption at rest
- Implement proper user authentication
- Add rate limiting and input validation

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/secure-file-storage.git

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install pytest pytest-flask  # For testing

# Run tests
pytest

# Run with debug mode
python app.py
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security Disclaimers

### Current Implementation (Phase 2)
- **Educational purposes**: This is a learning project demonstrating encryption concepts
- **Single-user**: Currently designed for single-user scenarios
- **JSON storage**: Uses JSON files instead of proper database (development only)
- **Key display**: Shows keys in `/keys` endpoint for debugging (remove in production)

### Production Considerations
- Implement proper user authentication
- Use encrypted database storage
- Add key derivation from passwords
- Implement secure key backup/recovery
- Add audit logging
- Use hardware security modules (HSM) for key storage
- Implement proper session management
- Add CSRF protection and input validation

## 🆘 Troubleshooting

### Common Issues

**ImportError: No module named 'Crypto'**
```bash
pip install pycryptodome
# NOT pycrypto (deprecated)
```

**Files not encrypting**
```bash
# Check that crypto_utils.py is in your project folder
# Verify pycryptodome is installed correctly
python -c "from Crypto.Cipher import AES; print('OK')"
```

**Permission errors on Windows**
```bash
# Run terminal as administrator or use:
pip install --user pycryptodome
```

**Downloads failing**
```bash
# Check that user_keys.json exists
# Verify file_metadata.json is not corrupted
# Ensure encrypted_uploads/ folder exists
```

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/YOUR_USERNAME/secure-file-storage/issues)
- **Discussions**: [GitHub Discussions](https://github.com/YOUR_USERNAME/secure-file-storage/discussions)
- **Security**: For security-related issues, please email directly instead of opening public issues

## 🙏 Acknowledgments

- **pycryptodome** - Excellent Python cryptography library
- **Flask** - Lightweight and powerful web framework
- **Cryptography community** - For best practices and security guidance

## 📈 Roadmap

### Short Term (Next Month)
- [ ] User authentication system
- [ ] File sharing capabilities
- [ ] Database integration (SQLite/PostgreSQL)
- [ ] Improved error handling

### Medium Term (3-6 Months)  
- [ ] React frontend
- [ ] RESTful API
- [ ] Cloud deployment guides
- [ ] Mobile app compatibility

### Long Term (6+ Months)
- [ ] Multi-tenant architecture
- [ ] Enterprise features
- [ ] Third-party integrations
- [ ] Advanced analytics

---

**⭐ Star this repo if you found it helpful!**

**🔐 Built with security and privacy in mind.**