# SecureNetShare
A Secure, Multi-Threaded File Sharing System with AES-256 Encryption & Integrity Verification

![C++](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Ubuntu-lightgrey.svg)
![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0.2-blue.svg)

---

## Overview
SecureNetShare is a secure client–server file transfer system built in C++17 using sockets and OpenSSL.  
It supports reliable file uploads/downloads with SHA-256 integrity verification and optional AES-256-CBC encryption for confidential file exchange.

Designed for the *Linux OS & Systems Programming Capstone Project* to demonstrate applied cybersecurity, encryption, and concurrent networking in C++.


<img width="1920" height="1080" alt="Screenshot (543)" src="https://github.com/user-attachments/assets/eae0b305-e281-4232-861c-1c7be1d73e85" />


<img width="1920" height="1080" alt="Screenshot (544)" src="https://github.com/user-attachments/assets/b3c50f84-03f2-4df0-82a1-84db5399a94b" />


<img width="1920" height="1080" alt="Screenshot (545)" src="https://github.com/user-attachments/assets/6a84f1df-1e8f-4b96-8294-00de59befc27" />


<img width="1920" height="1080" alt="Screenshot (546)" src="https://github.com/user-attachments/assets/a702f9df-b748-42fb-9e30-dc1fef2c051c" />


---

## Features
| Command | Description | Security |
|----------|--------------|-----------|
| LIST | List files on the server | – |
| GET | Download a file with SHA-256 verification | Integrity |
| GETENC | Download a file encrypted with AES-256-CBC | Confidentiality + Integrity |
| PUT | Upload a file with SHA-256 verification | Integrity |
| PUTENC (optional) | Future encrypted upload command | Planned |
| EXIT | Close client connection | – |

---

## Architecture
- Client: Handles user commands, encryption/decryption, and integrity checks  
- Server: Multi-threaded TCP service, manages files, and validates uploads  
- Crypto: AES-256-CBC and SHA-256 hashing (OpenSSL)  
- Utils: Logging, timestamping, and helper utilities  

### Project Structure
```
SecureNetShare/
├── src/
│   ├── client.cpp
│   ├── server.cpp
│   ├── crypto.cpp
│   ├── utils.cpp
│   ├── main_client.cpp
│   ├── main_server.cpp
|── include/
│   ├── client.hpp
│   ├── server.hpp
│   ├── crypto.hpp
│   └── utils.hpp
│
├── data/
│   ├── server_files/test.txt
│   └── client_files/test.txt
│
├── build/
└── CMakeLists.txt
```

---

## Security Implementation
| Mechanism | Purpose |
|------------|----------|
| SHA-256 Hashing | Verifies integrity of all transfers |
| AES-256-CBC Encryption | Secures files in transit |
| Password-Derived Key (KDF) | Derives 256-bit AES key |
| Random IV | Ensures unique ciphertexts |
| Integrity Before Acknowledgment | Server verifies file hash before confirmation |

---

## Requirements
- Ubuntu 22.04+ / WSL2  
- CMake ≥ 3.16  
- GCC ≥ 9.5  
- OpenSSL ≥ 3.0  

Install dependencies:
```bash
sudo apt update
sudo apt install build-essential cmake libssl-dev
```

---

## Build Instructions
```bash
git clone https://github.com/<your-username>/SecureNetShare.git
cd SecureNetShare
mkdir build && cd build
cmake ..
make -j$(nproc)
```

---

## Usage Guide
Start the server:
```bash
./build/server
```
Output:
```
[Sun Nov  9 01:14:18 2025] Server listening on port 8080
```

Run the client:
```bash
./build/client
```

Commands:
```
LIST | GET <filename> | GETENC <filename> | PUT <localpath> | PUTENC <localpath> | EXIT
```

Example session:
```
> LIST
test.txt

> GET test.txt
[Sun ...] File downloaded successfully (SHA-256 verified).

> GETENC test.txt
Password: mysecret
[Sun ...] Encrypted download verified (SHA-256 OK).

> PUT data/client_files/test.txt
[Sun ...] Upload complete.
```

---

## Logging
All operations are logged with timestamps:
```
[Sun Nov  9 01:14:42 2025] Client command: PUT test.txt
[Sun Nov  9 01:14:42 2025] File test.txt uploaded and verified OK.
```

---

## Cryptographic Functions
| Function | Description |
|-----------|--------------|
| sha256_file(path) | Returns SHA-256 hash of file |
| kdf_sha256_key32(password, key) | Derives AES-256 key |
| aes256_cbc_encrypt_file_to_socket(path, sock, key, iv) | Encrypts and streams file |
| aes256_cbc_decrypt_socket_to_file(sock, size, path, key, iv) | Decrypts streamed file |
| to_hex(data) / hex_to_bytes(hex) | Converts between binary and hex |

---

## Tested On
| Component | Version |
|------------|----------|
| Ubuntu | 22.04 LTS |
| Compiler | GCC 9.5.0 |
| CMake | 3.22.1 |
| OpenSSL | 3.0.2 |
| Environment | WSL2 |

---

## Future Enhancements
- Implement PUTENC (encrypted uploads)  
- Add user authentication  
- Add TLS handshake or RSA key exchange  
- Build GUI frontend in Qt or React  

---

## Author
Anoushka Aditi Acharya  
Capstone Project – Network Security & Systems Programming  
Environment: Ubuntu 22.04 (WSL) | C++17 | OpenSSL 3.0 | Multi-threaded sockets  

---


