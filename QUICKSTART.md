# Quick Start Guide

## Prerequisites
- OpenSSL libraries installed
- C++ compiler (g++ or clang++)
- Python 3 with matplotlib and pandas (for Experiment D)

## Building

### Linux/macOS:
```bash
make all
```

### Windows:
```bash
build.bat
```

## Running Experiments

### Experiment A: Basic TCP
**Terminal 1:**
```bash
./receiver_a
```

**Terminal 2:**
```bash
./sender_a msg "Hello World"
./sender_a file test.txt
```

### Experiment B: Diffie-Hellman + AES-128-CBC
**Terminal 1:**
```bash
./receiver_b
```

**Terminal 2:**
```bash
./sender_b msg "Hello World"
./sender_b file test.txt
```

### Experiment C: RSA-3072 with OAEP
**Terminal 1:**
```bash
./receiver_c
# Generates receiver_private.pem and receiver_public.pem
```

**Terminal 2:**
```bash
# Make sure receiver_public.pem exists
./sender_c msg "Hello World"
./sender_c file test.txt
```

### Experiment D: Performance Testing

1. Generate 1KB test file:
```bash
./generate_test_file
```

2. Start both receivers:
```bash
# Terminal 1
./receiver_b

# Terminal 2  
./receiver_c
```

3. Run performance test (100 runs):
```bash
./test_performance test_1kb.bin 100
```

4. Generate plot:
```bash
python3 plot_results.py
# Output: performance_comparison.png
```

## Expected Results

- **Experiment A**: Basic message and file transfer works
- **Experiment B**: Encrypted communication using AES-128-CBC
- **Experiment C**: Encrypted communication using RSA-3072
- **Experiment D**: Plot showing RSA is significantly slower than AES for file encryption

## Troubleshooting

1. **Port already in use**: Kill existing processes or change ports in source code
2. **OpenSSL not found**: Install OpenSSL and ensure libraries are in PATH
3. **Connection refused**: Make sure receiver is running before sender
4. **RSA key not found**: Run receiver_c first to generate keys
