CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wno-deprecated-declarations -Wno-unknown-pragmas -Wno-unused-but-set-variable -Wno-sign-compare -O2
OPENSSL_FLAGS = -lssl -lcrypto

# Windows-specific flags
ifeq ($(OS),Windows_NT)
    LDFLAGS = -lws2_32 $(OPENSSL_FLAGS)
else
    LDFLAGS = $(OPENSSL_FLAGS)
endif

# Experiment A (Basic TCP)
sender_a: sender_a.cpp
	$(CXX) $(CXXFLAGS) -o sender_a.exe sender_a.cpp $(LDFLAGS)

receiver_a: receiver_a.cpp
	$(CXX) $(CXXFLAGS) -o receiver_a.exe receiver_a.cpp $(LDFLAGS)

# Experiment B (DH + AES)
sender_b: sender_b.cpp
	$(CXX) $(CXXFLAGS) -o sender_b.exe sender_b.cpp $(LDFLAGS)

receiver_b: receiver_b.cpp
	$(CXX) $(CXXFLAGS) -o receiver_b.exe receiver_b.cpp $(LDFLAGS)

# Experiment C (RSA)
sender_c: sender_c.cpp
	$(CXX) $(CXXFLAGS) -o sender_c.exe sender_c.cpp $(LDFLAGS)

receiver_c: receiver_c.cpp
	$(CXX) $(CXXFLAGS) -o receiver_c.exe receiver_c.cpp $(LDFLAGS)

# Performance testing
test_performance: test_performance.cpp
	$(CXX) $(CXXFLAGS) -o test_performance.exe test_performance.cpp $(LDFLAGS)

# Test file generator
generate_test_file: generate_test_file.cpp
	$(CXX) $(CXXFLAGS) -o generate_test_file.exe generate_test_file.cpp

# Build all
all: sender_a receiver_a sender_b receiver_b sender_c receiver_c test_performance generate_test_file

# Clean
clean:
	rm -f *.exe
	rm -f *.pem *.bin performance_results.csv performance_plot.png

.PHONY: all clean