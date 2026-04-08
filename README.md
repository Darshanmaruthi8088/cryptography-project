# Crypto Security Toolkit

## Overview
This project is a Flask-based security toolkit focused on handwritten cryptographic and security algorithms for academic learning and demos.

Core capabilities:
- Custom hybrid cipher: Vigenere (byte mode) + XOR + bit rotation with PBKDF2-derived keystream
- Steganography: LSB hide/extract with capacity checks and detection heuristics
- GIF malware scanner: signature matching + entropy-based heuristic scoring
- Handwritten SHA-256 and PBKDF2-HMAC-SHA256
- RSA key generation, encryption/decryption, and digital signature demo
- Diffie-Hellman key exchange simulation
- File encryption/decryption workflow (`.cst` payload format)
- Benchmark dashboard endpoint for performance comparisons

## Architecture
Backend modules:
- `app.py`: Flask routes, validation, error handling, rate limiting, file APIs
- `crypto_algorithms.py`: hybrid text/file encryption logic
- `hash_algorithms.py`: handwritten SHA-256, HMAC-SHA256, PBKDF2
- `rsa_algorithms.py`: RSA primitives and signatures
- `diffie_hellman.py`: DH simulation
- `steganography.py`: hide/extract/detect LSB data
- `malware_scanner.py`: GIF scanner and entropy analysis
- `validators.py`: input and file validation
- `rate_limiter.py`: in-memory request throttling
- `benchmarking.py`: algorithm timing comparisons

Frontend:
- `templates/index.html`
- `static/style.css`
- `static/script.js`

## Setup
### 1. Create virtual environment
```powershell
python -m venv .venv
.\.venv\Scripts\activate
```

### 2. Install dependencies
```powershell
pip install -r requirements.txt
```

### 3. Run the app
```powershell
python app.py
```

Open: `http://127.0.0.1:5000`

## Commands
Run tests:
```powershell
python -m unittest discover -s tests -v
```

Optional debug mode:
```powershell
$env:FLASK_DEBUG=\"1\"
python app.py
```

## Deployment
### Procfile (for process-based hosts)
`web: python app.py`

### Docker
```powershell
docker build -t crypto-toolkit .
docker run -p 5000:5000 crypto-toolkit
```

## Security Notes
- This project is educational. Do not use it to protect production secrets.
- RSA demo mode prioritizes clarity over production hardening.
- In-memory rate limiting resets when the process restarts.
- Prefer PNG/BMP for steganography (lossy formats can damage hidden data).

## Testing Scope
Current tests include:
- Hash correctness (`SHA-256`, `PBKDF2`)
- Hybrid cipher round-trips and legacy decrypt compatibility
- RSA encrypt/decrypt and sign/verify
- Steganography hide/extract and capacity failures
- GIF scanner behavior
- Flask API smoke/integration checks

