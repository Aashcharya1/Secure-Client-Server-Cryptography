# Lab 3: Secure Client-Server Communication

This project implements secure client-server communication using TCP sockets with various encryption methods.

## Experiments

- **Experiment A**: Basic TCP client-server communication with message and file transfer
- **Experiment B**: Diffie-Hellman key exchange + AES-128-CBC encryption
- **Experiment C**: RSA-3072 encryption with OAEP padding
- **Experiment D**: Performance comparison between AES and RSA (100 runs)

## Prerequisites

- C++ compiler (g++ or clang++)
- OpenSSL development libraries
- Python 3 with matplotlib and pandas (for plotting results)
- On Windows: MinGW or Visual Studio with OpenSSL

### Installing OpenSSL

**Linux:**
```bash
sudo apt-get install libssl-dev  # Ubuntu/Debian
sudo yum install openssl-devel    # CentOS/RHEL
```

**Windows:**
- Download OpenSSL from https://slproweb.com/products/Win32OpenSSL.html
- Or use vcpkg: `vcpkg install openssl`

**macOS:**
```bash
brew install openssl
```

## Building

### Using Makefile (Linux/macOS):
```bash
make all
```

### Manual compilation:
```bash
# Experiment A
g++ -std=c++11 -o sender_a sender.cpp -lssl -lcrypto
g++ -std=c++11 -o receiver_a receiver.cpp -lssl -lcrypto

# Experiment B
g++ -std=c++11 -o sender_b sender_b.cpp -lssl -lcrypto
g++ -std=c++11 -o receiver_b receiver_b.cpp -lssl -lcrypto

# Experiment C
g++ -std=c++11 -o sender_c sender_c.cpp -lssl -lcrypto
g++ -std=c++11 -o receiver_c receiver_c.cpp -lssl -lcrypto

# Performance testing
g++ -std=c++11 -o test_performance test_performance.cpp -lssl -lcrypto

# Test file generator
g++ -std=c++11 -o generate_test_file generate_test_file.cpp
```

### Windows (with MinGW):
```bash
g++ -std=c++11 -o sender_a sender.cpp -lws2_32 -lssl -lcrypto
g++ -std=c++11 -o receiver_a receiver.cpp -lws2_32 -lssl -lcrypto
# ... similar for other programs
```

## Running Experiments

### Experiment A: Basic TCP Communication

**Terminal 1 (Receiver):**
```bash
./receiver_a
```

**Terminal 2 (Sender):**
```bash
# Send a message
./sender_a msg "Hello, World!"

# Send a file
./sender_a file test.txt
```

### Experiment B: Diffie-Hellman + AES-128-CBC

**Terminal 1 (Receiver):**
```bash
./receiver_b
```

**Terminal 2 (Sender):**
```bash
# Send a message
./sender_b msg "Hello, World!"

# Send a file
./sender_b file test.txt
```

### Experiment C: RSA-3072 with OAEP

**Terminal 1 (Receiver):**
```bash
./receiver_c
# This will generate receiver_private.pem and receiver_public.pem
```

**Terminal 2 (Sender):**
```bash
# Make sure receiver_public.pem exists in the same directory
./sender_c msg "Hello, World!"

# Send a file
./sender_c file test.txt
```

### Experiment D: Performance Testing

1. **Generate a 1KB test file:**
```bash
./generate_test_file
# Creates test_1kb.bin
```

2. **Start receivers in separate terminals:**
```bash
# Terminal 1
./receiver_b

# Terminal 2
./receiver_c
```

3. **Run performance test:**
```bash
./test_performance test_1kb.bin 100
# This will create performance_results.csv
```

4. **Generate comparison plot:**
```bash
python3 plot_results.py
# Or: python plot_results.py
# Creates performance_comparison.png
```

## File Structure

```
.
├── sender.cpp              # Experiment A sender
├── receiver.cpp            # Experiment A receiver
├── sender_b.cpp            # Experiment B sender (DH + AES)
├── receiver_b.cpp          # Experiment B receiver (DH + AES)
├── sender_c.cpp            # Experiment C sender (RSA)
├── receiver_c.cpp          # Experiment C receiver (RSA)
├── test_performance.cpp    # Performance testing tool
├── generate_test_file.cpp  # Test file generator
├── plot_results.py         # Python script for plotting
├── Makefile               # Build configuration
└── README.md              # This file
```

## Notes

- **Ports**: Experiment A and B use port 8080, Experiment C uses port 8081
- **Key Files**: RSA keys are stored as PEM files (receiver_private.pem, receiver_public.pem)
- **Performance**: The test_performance tool measures encryption time from sender to receiver decryption
- **RSA Chunking**: For files larger than the RSA block size, files are split into chunks and encrypted separately

## Troubleshooting

1. **Connection refused**: Make sure the receiver is running before starting the sender
2. **OpenSSL errors**: Ensure OpenSSL libraries are properly installed and linked
3. **Permission denied**: On Linux, ports below 1024 may require sudo (these programs use ports 8080/8081)
4. **RSA key not found**: Run receiver_c first to generate the public key file

## Results

After running Experiment D, you should see:
- `performance_results.csv`: Raw timing data
- `performance_comparison.png`: Line plot comparing AES vs RSA performance

The plot shows encryption time (in milliseconds) for each of the 100 runs, clearly demonstrating that AES-128-CBC is significantly faster than RSA-3072 for file encryption.
