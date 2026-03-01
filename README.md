# Secure Client-Server Cryptography 

![Language](https://img.shields.io/badge/Language-C++11-blue.svg)
![Cryptography](https://img.shields.io/badge/Crypto-OpenSSL%203.0-brightgreen.svg)
![Networking](https://img.shields.io/badge/Network-TCP%2FIP-orange.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)

## 📑 Table of Contents
1. [Project Abstract](#-project-abstract)
2. [Cryptographic Architecture](#-cryptographic-architecture)
3. [Engineering Solutions & Constraints](#-engineering-solutions--constraints)
4. [Environment & Prerequisites](#-environment--prerequisites)
5. [Build Instructions](#-build-instructions)
6. [Execution Guide](#-execution-guide)
7. [Performance Benchmarking](#-performance-benchmarking)
8. [Repository Structure](#-repository-structure)

---

## 📖 Project Abstract

This project implements a secure, custom client-server file transfer and messaging protocol over TCP sockets. It demonstrates the evolutionary implementation of network security, progressing from raw, unencrypted byte streams to robust symmetric and asymmetric cryptographic channels. 

The system is built entirely in C++ using the modern OpenSSL `EVP` API, ensuring that all cryptographic operations adhere to current industry standards (avoiding deprecated, insecure APIs).



---

## 🔐 Cryptographic Architecture

The project is divided into four primary experiments, each building upon the last:

### Experiment A: Raw TCP Sockets
Establishes the foundational network layer using POSIX/Winsock2 sockets. It implements a custom application-layer protocol defining boundaries for both short string messages and binary file payloads.

### Experiment B: Symmetric Channel (Diffie-Hellman + AES-128-CBC)
Secures the TCP stream using symmetric cryptography.
* **Key Exchange:** Utilizes a 2048-bit Diffie-Hellman exchange (`DH_generate_parameters_ex`) to negotiate a shared secret over an insecure channel.
* **Key Derivation:** The variable-length DH shared secret is cryptographically hashed using **SHA-256** to deterministically extract a 16-byte key and 16-byte Initialization Vector (IV).
* **Encryption:** Payloads are encrypted using **AES-128 in Cipher Block Chaining (CBC)** mode.



### Experiment C: Asymmetric Channel (RSA-3072 + OAEP)
Secures the TCP stream using public-key cryptography.
* **Key Generation:** Generates a robust 3072-bit RSA key pair.
* **Padding:** Implements strict **Optimal Asymmetric Encryption Padding (OAEP)** with a **SHA-256** digest (`RSA_PKCS1_OAEP_PADDING`). This ensures semantic security, preventing deterministic ciphertext analysis.



### Experiment D: Cryptographic Benchmarking
An automated testing suite that executes 100 sequential 1KB file transfers across both the AES and RSA channels to measure and plot the exact computational overhead of symmetric vs. asymmetric encryption.

---

## ⚙️ Engineering Solutions & Constraints

To achieve reliable encrypted file transfers, several complex network and cryptographic constraints were resolved:

1. **TCP Stream Merging (Buffer Misalignment):**
   TCP is a continuous stream protocol. Rapidly sending sequential encrypted blocks causes payloads to merge in the receiver's buffer, triggering OpenSSL padding exceptions ("bad decrypt"). 
   * *Solution:* Implemented a strict **Length-Prefixing Protocol**. The sender transmits a 4-byte `uint32_t` (converted to network byte order via `htonl`) representing the exact ciphertext size. The receiver utilizes a custom `recvAll` loop to guarantee byte-perfect buffer alignment before passing data to the `EVP_CIPHER_CTX`.

2. **RSA Asymmetric Block Size Limits:**
   Unlike AES, RSA cannot process bulk data. A 3072-bit RSA key cannot encrypt a full 1KB file in a single pass due to key-size limitations and OAEP padding overhead.
   * *Solution:* Engineered a dynamic chunking algorithm. With a 384-byte key size and 66 bytes of OAEP SHA-256 overhead ($2 \times 32 + 2$), the maximum safe plaintext payload is exactly **318 bytes**. The software automatically slices larger files into 318-byte chunks, encrypts them individually, and safely concatenates them.

---

## 💻 Environment & Prerequisites

* **Compiler:** `g++` (GCC) with C++11 support minimum.
* **Cryptography:** OpenSSL Development Libraries (`libssl`, `libcrypto`).
* **Networking:** `ws2_32` (Windows only).
* **Data Visualization:** Python 3 with `pandas` and `matplotlib`.

### Python Dependencies (For Exp D)
```bash
pip install pandas matplotlib
```

## 🔨 Build Instructions

Automated build scripts are provided for both Windows and UNIX-based systems.

### Windows (MinGW64 / MSYS2)
Ensure your MinGW bin is in your PATH. Run the provided batch script:

```dos
build.bat
```

**Troubleshooting:** If .exe files crash immediately upon execution, copy `libssl-3-x64.dll` and `libcrypto-3-x64.dll` from your MinGW bin directory directly into the project folder.

### Linux / macOS
Use the provided Makefile:

```bash
make all
```

## 🚀 Execution Guide

**Note:** For all experiments, the Receiver terminal must be started before the Sender terminal to bind the listening port.

### Experiment A (Cleartext)
**Receiver:** `./receiver_a.exe`

**Sender:** `./sender_a.exe msg "Test Message"` OR `./sender_a.exe file target.txt`

### Experiment B (AES-128)
**Receiver:** `./receiver_b.exe`

**Sender:** `./sender_b.exe msg "Secure Message"` OR `./sender_b.exe file target.txt`

### Experiment C (RSA-3072)
**Important:** You must run the receiver first to generate the required `receiver_public.pem` file.

**Receiver:** `./receiver_c.exe`

**Sender:** `./sender_c.exe msg "Asymmetric Message"` OR `./sender_c.exe file target.txt`

## 📊 Performance Benchmarking (Experiment D)

To execute the 100-run benchmark comparing AES vs RSA performance:

1. Generate the precise 1KB payload:

```bash
./generate_test_file.exe
```

2. Launch both cryptographic listening servers:

- **Terminal 1:** `./receiver_b.exe` (Binds Port 8080)
- **Terminal 2:** `./receiver_c.exe` (Binds Port 8081)

3. Execute the benchmark suite:

**Terminal 3:** `./test_performance.exe test_1kb.bin 100`

4. Generate the visualization plot:

```bash
python plot.py
```

This reads the generated `performance_results.csv` and outputs `performance_plot.png`.

## 📂 Repository Structure

```
📦 CSL6010-Lab3
 ┣ 📜 sender.cpp                 # Exp A: Cleartext Socket Client
 ┣ 📜 receiver.cpp               # Exp A: Cleartext Socket Server
 ┣ 📜 senderB.cpp                # Exp B: DH Exchange & AES-128 Client
 ┣ 📜 receiverB.cpp              # Exp B: DH Exchange & AES-128 Server
 ┣ 📜 senderC.cpp                # Exp C: RSA-3072 Encryption Client
 ┣ 📜 receiverC.cpp              # Exp C: RSA-3072 Decryption Server
 ┣ 📜 test_performance.cpp       # Exp D: 100-run Benchmark Wrapper
 ┣ 📜 generate_test_file.cpp     # Exp D: 1KB Binary Payload Generator
 ┣ 📜 plot.py                    # Exp D: Matplotlib Visualization Script
 ┣ 📜 Makefile                   # UNIX Build Automation
 ┣ 📜 build.bat                  # Windows Build Automation
 ┗ 📜 README.md                  # Comprehensive Documentation
```
