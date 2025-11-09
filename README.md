
# 🛡️ SecureNetShare  
*A Secure, Multi-Threaded File Sharing System with AES-256 Encryption & Integrity Verification*

![C++](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Ubuntu-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0.2-blue.svg)

---

## 📘 Overview

**SecureNetShare** is a secure client–server file transfer system built in C++ using **sockets** and **OpenSSL**.  
It supports reliable file uploads/downloads with **SHA-256 integrity verification** and optional **AES-256-CBC encryption** for confidential file exchange.

> 🧠 Designed for the *Linux OS & Systems Programming Capstone Project* to demonstrate applied cybersecurity, encryption, and concurrent networking in C++.

---

## ✨ Features

| Command | Description | Security |
|----------|--------------|-----------|
| `LIST` | List files on the server | – |
| `GET` | Download a file with SHA-256 verification | ✅ Integrity |
| `GETENC` | Download a file encrypted with AES-256-CBC | ✅ Confidentiality + Integrity |
| `PUT` | Upload a file with SHA-256 verification | ✅ Integrity |
| `PUTENC` *(optional)* | Future encrypted upload command | 🚧 Planned |
| `EXIT` | Close client connection | – |

---

## ⚙️ Architecture



┌──────────────┐ TCP Socket ┌──────────────┐
│ Client │ <------------------------> │ Server │
│ │ Commands: LIST / GET ... │ │
│ │ Encrypted file streams │ │
│ │<---------------------------->│ │
└──────────────┘ └──────────────┘


- **Client:** Handles user commands, encryption/decryption, and integrity checks  
- **Server:** Multi-threaded TCP service, manages files, and validates uploads  
- **Crypto:** AES-256-CBC and SHA-256 hashing (OpenSSL)  
- **Utils:** Logging, timestamping, and helper utilities  

---

## 🧠 Security Implementation

| Mechanism | Purpose |
|------------|----------|
| **SHA-256 Hashing** | Verifies integrity of all transfers |
| **AES-256-CBC Encryption** | Secures files in transit (`GETENC`) |
| **Password-Derived Key (KDF)** | Derives 256-bit AES key via SHA-256 |
| **Random IV** | Ensures unique ciphertexts per session |
| **Integrity Before Acknowledgment** | Server verifies file hash before confirming upload |

---

## 📁 Project Structure



SecureNetShare/
├── src/
│ ├── client.cpp # Client logic & commands
│ ├── server.cpp # Multi-threaded server handler
│ ├── crypto.cpp # AES + SHA256 (OpenSSL)
│ ├── utils.cpp # Logging & helper functions
│ ├── main_client.cpp
│ ├── main_server.cpp
│ ├── client.hpp
│ ├── server.hpp
│ ├── crypto.hpp
│ └── utils.hpp
│
├── data/
│ ├── server_files/ # Server-side file store
│ └── client_files/ # Client download/upload folder
│
├── build/ # Compiled binaries
└── CMakeLists.txt # CMake configuration


---

## 🧰 Requirements

### 🛠️ Dependencies
- **Ubuntu 22.04+ / WSL2**
- **CMake ≥ 3.16**
- **GCC ≥ 9.5**
- **OpenSSL 3.0+**

Install with:
```bash
sudo apt update
sudo apt install build-essential cmake libssl-dev

⚙️ Build Instructions
# Clone and setup
git clone https://github.com/<your-username>/SecureNetShare.git
cd SecureNetShare
mkdir build && cd build

# Build project
cmake ..
make -j$(nproc)

🚀 Usage Guide
1️⃣ Start the Server
./build/server


Output:

[Sun Nov  9 01:14:18 2025] Server listening on port 8080

2️⃣ Run the Client
./build/client

3️⃣ Available Commands
Commands: LIST | GET <filename> | GETENC <filename> | PUT <localpath> | PUTENC <localpath> | EXIT

4️⃣ Example Session
🗂️ List Files
> LIST
test.txt

📥 Download File
> GET test.txt
[Sun ...] Downloading test.txt (36 bytes) ...
[Sun ...] File downloaded successfully (SHA-256 verified).

🔐 Encrypted Download
> GETENC test.txt
Password: mysecret
[Sun ...] Downloading test.txt (encrypted 48 bytes) ...
[Sun ...] Encrypted download verified (SHA-256 OK).

📤 Upload File
> PUT data/client_files/test.txt
[Sun ...] Upload complete.

🧾 Logging

All operations are logged with timestamps:

[Sun Nov  9 01:14:42 2025] Client command: PUT test.txt
[Sun Nov  9 01:14:42 2025] File test.txt uploaded and verified OK.


Logs are written to both server and client consoles for clarity.

🔒 Cryptographic Functions
Function	Description
sha256_file(path)	Returns SHA-256 hash of file
kdf_sha256_key32(password, key)	Derives AES-256 key from user password
aes256_cbc_encrypt_file_to_socket(path, sock, key, iv)	Encrypts and streams file
aes256_cbc_decrypt_socket_to_file(sock, size, path, key, iv)	Decrypts streamed file to disk
to_hex(data) / hex_to_bytes(hex)	Converts between binary and hex for IVs
🧪 Tested On
Component	Version
Ubuntu	22.04 LTS
Compiler	GCC 9.5.0
CMake	3.22.1
OpenSSL	3.0.2
WSL2 Environment
🧭 Future Enhancements

 Implement PUTENC (encrypted uploads)

 Add user authentication

 Add TLS handshake or RSA key exchange

 Build GUI frontend in Qt or React

🧑‍💻 Author

    Anoushka Aditi Acharya
🎓 Capstone Project – Network Security & Systems Programming
💻 Environment: Ubuntu 22.04 (WSL) | C++17 | OpenSSL 3.0 | Multi-threaded sockets


📄 License

This project is licensed under the MIT License — see LICENSE
 for details.

⭐ SecureNetShare — Transfer with Trust. Verify with Hash.


---

### ✅ Notes for GitHub:
- Place this file at the root of your repo (`SecureNetShare/README.md`).
- Add a `LICENSE` file (MIT recommended).
- Push with:
  ```bash
  git add README.md LICENSE
  git commit -m "Added project documentation"
  git push