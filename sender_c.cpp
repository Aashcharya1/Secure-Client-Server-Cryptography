#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <chrono>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

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

const int PORT = 8081;
const int BUFFER_SIZE = 4096;
const int RSA_KEY_SIZE_BYTES = 384; // 3072 bits
// 384 - 2*(SHA256_length) - 2 = 384 - 64 - 2 = 318
const int RSA_CHUNK_SIZE = 318; 

bool recvAll(int sock, char* buf, int len) {
    int total = 0;
    while (total < len) {
        int n = recv(sock, buf + total, len - total, 0);
        if (n <= 0) return false;
        total += n;
    }
    return true;
}

void printHex(const std::string& label, const std::vector<unsigned char>& data) {
    std::cout << label << ":\n";
    for (unsigned char c : data) {
        printf("%02x", c);
    }
    std::cout << "\n\n";
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

EVP_PKEY* loadPublicKey(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) return nullptr;
    
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

std::vector<unsigned char> encryptRSA(const std::vector<unsigned char>& plaintext, EVP_PKEY* pkey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    
    // Rubric Requirement: OAEP with SHA-256
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    
    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext.data(), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    
    std::vector<unsigned char> ciphertext(outlen);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    
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
        if (encrypted_chunk.empty()) return {};
        
        encrypted_data.insert(encrypted_data.end(), encrypted_chunk.begin(), encrypted_chunk.end());
    }
    return encrypted_data;
}

void sendMessage(int sock, const std::string& message, EVP_PKEY* pkey) {
    std::string command = "MSG:" + message;
    std::vector<unsigned char> plaintext(command.begin(), command.end());
    
    std::cout << "--- Outgoing Message ---" << std::endl;
    std::cout << "Original Plaintext: " << command << std::endl;
    
    std::vector<unsigned char> encrypted = encryptRSA(plaintext, pkey);
    if (encrypted.empty()) return;
    
    // Rubric Requirement: Show encrypted text
    printHex("Generated Ciphertext (Hex)", encrypted);
    
    uint32_t encrypted_len = htonl(encrypted.size());
    send(sock, (char*)&encrypted_len, sizeof(encrypted_len), 0);
    send(sock, (char*)encrypted.data(), encrypted.size(), 0);
    
    uint32_t response_len;
    recvAll(sock, (char*)&response_len, sizeof(response_len));
    response_len = ntohl(response_len);
    
    char buffer[BUFFER_SIZE] = {0};
    recvAll(sock, buffer, response_len);
    std::cout << "Server Response: " << std::string(buffer, response_len) << std::endl;
}

double sendFile(int sock, const std::string& filename, EVP_PKEY* pkey) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return -1;
    
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> file_data(file_size);
    file.read((char*)file_data.data(), file_size);
    file.close();
    
    std::string command = "FILE NAME:" + filename + " SIZE:" + std::to_string(file_size) + "\n";
    std::vector<unsigned char> command_bytes(command.begin(), command.end());
    
    std::vector<unsigned char> encrypted_command = encryptRSA(command_bytes, pkey);
    
    uint32_t cmd_len = htonl(encrypted_command.size());
    send(sock, (char*)&cmd_len, sizeof(cmd_len), 0);
    send(sock, (char*)encrypted_command.data(), encrypted_command.size(), 0);
    
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<unsigned char> encrypted_file = encryptFileRSA(file_data, pkey);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double encryption_time = duration.count() / 1000.0;
    
    uint32_t file_encrypted_len = htonl(encrypted_file.size());
    send(sock, (char*)&file_encrypted_len, sizeof(file_encrypted_len), 0);
    send(sock, (char*)encrypted_file.data(), encrypted_file.size(), 0);
    
    std::cout << "\nFile encrypted and sent: " << filename << " (" << file_size << " bytes)" << std::endl;
    std::cout << "Encryption time: " << encryption_time << " ms" << std::endl;
    
    uint32_t ack_len;
    recvAll(sock, (char*)&ack_len, sizeof(ack_len));
    ack_len = ntohl(ack_len);
    
    char buffer[BUFFER_SIZE] = {0};
    recvAll(sock, buffer, ack_len);
    std::cout << "Server Response: " << std::string(buffer, ack_len) << std::endl;
    
    return encryption_time;
}

int main(int argc, char* argv[]) {
    initializeWinsock();
    
    EVP_PKEY* pkey = loadPublicKey("receiver_public.pem");
    if (!pkey) {
        std::cerr << "Ensure receiver_public.pem exists! Run receiverC.exe first." << std::endl;
        return 1;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    
    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    std::cout << "Connected to receiver\n" << std::endl;
    
    if (argc > 1) {
        std::string command = argv[1];
        if (command == "msg" && argc > 2) {
            sendMessage(sock, argv[2], pkey);
        }
        else if (command == "file" && argc > 2) {
            sendFile(sock, argv[2], pkey);
        }
    } else {
        std::string input, arg;
        std::cout << "Enter command (msg [text] OR file [name] OR exit): ";
        std::cin >> input;
        if (input == "msg") {
            std::getline(std::cin >> std::ws, arg);
            sendMessage(sock, arg, pkey);
        } else if (input == "file") {
            std::cin >> arg;
            sendFile(sock, arg, pkey);
        }
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
    cleanupWinsock();
    return 0;
}