#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <chrono>
#include <thread>
#include <iomanip>
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

const int PORT_AES = 8080;
const int PORT_RSA = 8081;
const int BUFFER_SIZE = 4096;
const int RSA_CHUNK_SIZE = 318; // 384 bytes - 66 bytes (OAEP SHA256 overhead)

struct KeyIV {
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
};

// --- Helpers ---
bool recvAll(int sock, char* buf, int len) {
    int total = 0;
    while (total < len) {
        int n = recv(sock, buf + total, len - total, 0);
        if (n <= 0) return false;
        total += n;
    }
    return true;
}

void initializeWinsock() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
}

void cleanupWinsock() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// --- Cryptography Functions ---

// UPDATED: Syncs P and G parameters with the receiver!
KeyIV performDHKeyExchange(int sock) {
    // 1. Receive P parameter
    uint32_t net_p_len;
    if (!recvAll(sock, (char*)&net_p_len, sizeof(net_p_len))) return {};
    int p_len = ntohl(net_p_len);
    std::vector<unsigned char> p_bytes(p_len);
    recvAll(sock, (char*)p_bytes.data(), p_len);
    BIGNUM* p = BN_bin2bn(p_bytes.data(), p_len, NULL);

    // 2. Receive G parameter
    uint32_t net_g_len;
    recvAll(sock, (char*)&net_g_len, sizeof(net_g_len));
    int g_len = ntohl(net_g_len);
    std::vector<unsigned char> g_bytes(g_len);
    recvAll(sock, (char*)g_bytes.data(), g_len);
    BIGNUM* g = BN_bin2bn(g_bytes.data(), g_len, NULL);

    // Apply exact same params to Sender
    DH* dh = DH_new();
    DH_set0_pqg(dh, p, NULL, g);
    DH_generate_key(dh);

    const BIGNUM *pub_key;
    DH_get0_key(dh, &pub_key, NULL);

    // 3. Receive Receiver's Public Key
    uint32_t receiver_pub_key_len;
    recvAll(sock, (char*)&receiver_pub_key_len, sizeof(receiver_pub_key_len));
    receiver_pub_key_len = ntohl(receiver_pub_key_len);
    std::vector<unsigned char> receiver_pub_key_bytes(receiver_pub_key_len);
    recvAll(sock, (char*)receiver_pub_key_bytes.data(), receiver_pub_key_len);
    BIGNUM* receiver_pub_key = BN_bin2bn(receiver_pub_key_bytes.data(), receiver_pub_key_len, NULL);

    // 4. Send our Public Key
    int pub_key_len = BN_num_bytes(pub_key);
    std::vector<unsigned char> pub_key_bytes(pub_key_len);
    BN_bn2bin(pub_key, pub_key_bytes.data());
    uint32_t len = htonl(pub_key_len);
    send(sock, (char*)&len, sizeof(len), 0);
    send(sock, (char*)pub_key_bytes.data(), pub_key_len, 0);

    // Compute Secret
    std::vector<unsigned char> shared_secret(DH_size(dh));
    int secret_len = DH_compute_key(shared_secret.data(), receiver_pub_key, dh);
    shared_secret.resize(secret_len);

    std::vector<unsigned char> aes_key(16), iv(16);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, shared_secret.data(), shared_secret.size());
    unsigned char hash[32];
    unsigned int hash_len;
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    memcpy(aes_key.data(), hash, 16);
    memcpy(iv.data(), hash + 16, 16);

    BN_free(receiver_pub_key);
    DH_free(dh);
    
    return {aes_key, iv};
}

std::vector<unsigned char> encryptAES(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data());
    
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len, ciphertext_len = 0;
    
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;
    
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    
    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::vector<unsigned char> encryptRSA(const std::vector<unsigned char>& plaintext, EVP_PKEY* pkey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    
    size_t outlen;
    EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext.data(), plaintext.size());
    std::vector<unsigned char> ciphertext(outlen);
    EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size());
    
    ciphertext.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return ciphertext;
}

std::vector<unsigned char> encryptFileRSA(const std::vector<unsigned char>& file_data, EVP_PKEY* pkey) {
    std::vector<unsigned char> encrypted_data;
    for (size_t i = 0; i < file_data.size(); i += RSA_CHUNK_SIZE) {
        size_t current_chunk_size = std::min((size_t)RSA_CHUNK_SIZE, file_data.size() - i);
        std::vector<unsigned char> chunk(file_data.begin() + i, file_data.begin() + i + current_chunk_size);
        std::vector<unsigned char> encrypted_chunk = encryptRSA(chunk, pkey);
        encrypted_data.insert(encrypted_data.end(), encrypted_chunk.begin(), encrypted_chunk.end());
    }
    return encrypted_data;
}

// --- Benchmark Functions ---
std::vector<double> testAES(const std::vector<unsigned char>& file_data, int num_runs) {
    std::vector<double> times;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT_AES);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "AES connection failed. Is receiver_b.exe running on port " << PORT_AES << "?" << std::endl;
        return times;
    }
    
    KeyIV keyiv = performDHKeyExchange(sock);
    if (keyiv.key.empty()) {
        std::cerr << "DH Key Exchange failed in testAES" << std::endl;
        return times;
    }

    std::string command = "FILE NAME:aes_bench.bin SIZE:" + std::to_string(file_data.size()) + "\n";
    std::vector<unsigned char> cmd_bytes(command.begin(), command.end());
    
    for (int i = 0; i < num_runs; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<unsigned char> encrypted_cmd = encryptAES(cmd_bytes, keyiv.key, keyiv.iv);
        uint32_t cmd_len = htonl(encrypted_cmd.size());
        send(sock, (char*)&cmd_len, sizeof(cmd_len), 0);
        send(sock, (char*)encrypted_cmd.data(), encrypted_cmd.size(), 0);
        
        std::vector<unsigned char> encrypted = encryptAES(file_data, keyiv.key, keyiv.iv);
        uint32_t file_len = htonl(encrypted.size());
        send(sock, (char*)&file_len, sizeof(file_len), 0);
        send(sock, (char*)encrypted.data(), encrypted.size(), 0);
        
        char buffer[BUFFER_SIZE];
        uint32_t ack_len;
        recvAll(sock, (char*)&ack_len, sizeof(ack_len));
        ack_len = ntohl(ack_len);
        recvAll(sock, buffer, ack_len);
        
        auto end = std::chrono::high_resolution_clock::now();
        times.push_back(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0);
    }
    
    std::string exit_cmd = "EXIT";
    std::vector<unsigned char> exit_bytes(exit_cmd.begin(), exit_cmd.end());
    std::vector<unsigned char> encrypted_exit = encryptAES(exit_bytes, keyiv.key, keyiv.iv);
    uint32_t exit_len = htonl(encrypted_exit.size());
    send(sock, (char*)&exit_len, sizeof(exit_len), 0);
    send(sock, (char*)encrypted_exit.data(), encrypted_exit.size(), 0);
    
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    return times;
}

std::vector<double> testRSA(const std::vector<unsigned char>& file_data, int num_runs) {
    std::vector<double> times;
    FILE* fp = fopen("receiver_public.pem", "r");
    if (!fp) {
        std::cerr << "Failed to load receiver_public.pem" << std::endl;
        return times;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT_RSA);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "RSA connection failed. Is receiver_c.exe running on port " << PORT_RSA << "?" << std::endl;
        EVP_PKEY_free(pkey);
        return times;
    }
    
    std::string command = "FILE NAME:rsa_bench.bin SIZE:" + std::to_string(file_data.size()) + "\n";
    std::vector<unsigned char> cmd_bytes(command.begin(), command.end());
    
    for (int i = 0; i < num_runs; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<unsigned char> encrypted_cmd = encryptRSA(cmd_bytes, pkey);
        uint32_t cmd_len = htonl(encrypted_cmd.size());
        send(sock, (char*)&cmd_len, sizeof(cmd_len), 0);
        send(sock, (char*)encrypted_cmd.data(), encrypted_cmd.size(), 0);
        
        std::vector<unsigned char> encrypted = encryptFileRSA(file_data, pkey);
        uint32_t file_len = htonl(encrypted.size());
        send(sock, (char*)&file_len, sizeof(file_len), 0);
        send(sock, (char*)encrypted.data(), encrypted.size(), 0);
        
        char buffer[BUFFER_SIZE];
        uint32_t ack_len;
        recvAll(sock, (char*)&ack_len, sizeof(ack_len));
        ack_len = ntohl(ack_len);
        recvAll(sock, buffer, ack_len);
        
        auto end = std::chrono::high_resolution_clock::now();
        times.push_back(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0);
    }
    
    std::string exit_cmd = "EXIT";
    std::vector<unsigned char> exit_bytes(exit_cmd.begin(), exit_cmd.end());
    std::vector<unsigned char> encrypted_exit = encryptRSA(exit_bytes, pkey);
    uint32_t exit_len = htonl(encrypted_exit.size());
    send(sock, (char*)&exit_len, sizeof(exit_len), 0);
    send(sock, (char*)encrypted_exit.data(), encrypted_exit.size(), 0);
    
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    EVP_PKEY_free(pkey);
    return times;
}

int main(int argc, char* argv[]) {
    initializeWinsock();
    
    if (argc < 2) {
        std::cerr << "Usage: test_performance.exe <filename> [num_runs]" << std::endl;
        std::cerr << "Example: test_performance.exe test_1kb.bin 100" << std::endl;
        cleanupWinsock();
        return 1;
    }
    
    std::string filename = argv[1];
    int num_runs = (argc > 2) ? std::stoi(argv[2]) : 100;
    
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open " << filename << ". Run generate_test_file.exe first." << std::endl;
        return 1;
    }
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<unsigned char> file_data(file_size);
    file.read((char*)file_data.data(), file_size);
    file.close();
    
    std::cout << "Starting AES Benchmark (" << num_runs << " runs)..." << std::endl;
    std::vector<double> aes_times = testAES(file_data, num_runs);
    
    if (aes_times.empty()) {
        std::cerr << "AES Benchmark failed. Skipping to RSA..." << std::endl;
    }
    
    std::cout << "Starting RSA Benchmark (" << num_runs << " runs)..." << std::endl;
    std::vector<double> rsa_times = testRSA(file_data, num_runs);
    
    if (aes_times.size() == num_runs && rsa_times.size() == num_runs) {
        std::ofstream results_file("performance_results.csv");
        results_file << "Run,AES_Time_ms,RSA_Time_ms\n";
        for (int i = 0; i < num_runs; i++) {
            results_file << (i + 1) << "," << aes_times[i] << "," << rsa_times[i] << "\n";
            std::cout << "Run " << (i + 1) << " - AES: " << aes_times[i] << " ms | RSA: " << rsa_times[i] << " ms\n";
        }
        results_file.close();
        std::cout << "\nSuccess! Results saved to performance_results.csv" << std::endl;
    } else {
        std::cerr << "\nError: Benchmark did not complete successfully." << std::endl;
    }
    
    cleanupWinsock();
    return 0;
}