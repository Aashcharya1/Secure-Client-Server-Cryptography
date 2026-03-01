#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <chrono>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

const int PORT = 8081;
const int BUFFER_SIZE = 4096;

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

EVP_PKEY* loadOrGeneratePrivateKey() {
    EVP_PKEY* pkey = nullptr;
    FILE* fp = fopen("receiver_private.pem", "r");
    if (fp) {
        pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
        if (pkey) {
            std::cout << "Loaded existing private key" << std::endl;
            return pkey;
        }
    }
    
    std::cout << "Generating new RSA-3072 key pair..." << std::endl;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    
    fp = fopen("receiver_private.pem", "w");
    if (fp) {
        PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
        fclose(fp);
    }
    
    fp = fopen("receiver_public.pem", "w");
    if (fp) {
        PEM_write_PUBKEY(fp, pkey);
        fclose(fp);
    }
    
    std::cout << "RSA key pair generated and saved" << std::endl;
    return pkey;
}

std::vector<unsigned char> decryptRSA(const std::vector<unsigned char>& ciphertext, EVP_PKEY* pkey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_decrypt_init(ctx);
    
    // Rubric Requirement: OAEP with SHA-256
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    
    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    
    std::vector<unsigned char> plaintext(outlen);
    if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    
    plaintext.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return plaintext;
}

std::vector<unsigned char> decryptFileRSA(const std::vector<unsigned char>& encrypted_data, EVP_PKEY* pkey) {
    int rsa_size = EVP_PKEY_size(pkey); // 384 bytes for RSA-3072
    std::vector<unsigned char> decrypted_data;
    
    for (size_t i = 0; i < encrypted_data.size(); i += rsa_size) {
        size_t chunk_size = std::min((size_t)rsa_size, encrypted_data.size() - i);
        std::vector<unsigned char> chunk(encrypted_data.begin() + i, encrypted_data.begin() + i + chunk_size);
        
        std::vector<unsigned char> decrypted_chunk = decryptRSA(chunk, pkey);
        if (decrypted_chunk.empty()) return {};
        
        decrypted_data.insert(decrypted_data.end(), decrypted_chunk.begin(), decrypted_chunk.end());
    }
    return decrypted_data;
}

int main() {
    initializeWinsock();
    
    EVP_PKEY* pkey = loadOrGeneratePrivateKey();
    if (!pkey) return 1;
    
    std::cout << "Receiver public key saved to receiver_public.pem\n" << std::endl;
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);
    
    std::cout << "Receiver (RSA-3072 OAEP SHA-256) listening on port " << PORT << std::endl;
    
    socklen_t addrlen = sizeof(address);
    int client_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen);
    std::cout << "Connection accepted\n" << std::endl;

    while (true) {
        uint32_t encrypted_len;
        if (!recvAll(client_socket, (char*)&encrypted_len, sizeof(encrypted_len))) break;
        encrypted_len = ntohl(encrypted_len);
        
        std::vector<unsigned char> encrypted_data(encrypted_len);
        if (!recvAll(client_socket, (char*)encrypted_data.data(), encrypted_len)) break;
        
        // Rubric Requirement: Show Received Ciphertext
        std::cout << "--- Incoming Transmission ---" << std::endl;
        printHex("Received Ciphertext (Hex)", encrypted_data);
        
        auto start = std::chrono::high_resolution_clock::now();
        std::vector<unsigned char> decrypted = decryptRSA(encrypted_data, pkey);
        auto end = std::chrono::high_resolution_clock::now();
        
        if (decrypted.empty()) break;
        
        std::string message(decrypted.begin(), decrypted.end());
        
        // Rubric Requirement: Show Decrypted Plaintext
        std::cout << "Decrypted Plaintext: " << message << std::endl;
        
        if (message.substr(0, 4) == "MSG:") {
            std::string ack = "ACK: Message received";
            uint32_t ack_len = htonl(ack.length());
            send(client_socket, (char*)&ack_len, sizeof(ack_len), 0);
            send(client_socket, ack.c_str(), ack.length(), 0);
        }
        else if (message.substr(0, 4) == "FILE") {
            size_t name_pos = message.find("NAME:");
            size_t size_pos = message.find("SIZE:");
            
            if (name_pos != std::string::npos && size_pos != std::string::npos) {
                size_t name_end = message.find(" ", name_pos + 5);
                std::string filename = "recv_" + message.substr(name_pos + 5, name_end - name_pos - 5);
                
                uint32_t file_encrypted_len;
                recvAll(client_socket, (char*)&file_encrypted_len, sizeof(file_encrypted_len));
                file_encrypted_len = ntohl(file_encrypted_len);
                
                std::vector<unsigned char> file_encrypted(file_encrypted_len);
                recvAll(client_socket, (char*)file_encrypted.data(), file_encrypted_len);
                
                auto file_start = std::chrono::high_resolution_clock::now();
                std::vector<unsigned char> file_data = decryptFileRSA(file_encrypted, pkey);
                auto file_end = std::chrono::high_resolution_clock::now();
                
                if (file_data.empty()) break;
                
                auto duration = std::chrono::duration_cast<std::chrono::microseconds>(file_end - file_start);
                std::cout << "File decryption time: " << duration.count() / 1000.0 << " ms" << std::endl;
                
                std::ofstream outfile(filename, std::ios::binary);
                outfile.write((char*)file_data.data(), file_data.size());
                outfile.close();
                
                std::cout << "File saved as: " << filename << std::endl;
                
                std::string ack = "ACK: File received";
                uint32_t ack_len = htonl(ack.length());
                send(client_socket, (char*)&ack_len, sizeof(ack_len), 0);
                send(client_socket, ack.c_str(), ack.length(), 0);
            }
        }
        else if (message == "EXIT") {
            std::cout << "Exit command received" << std::endl;
            break;
        }
    }

#ifdef _WIN32
    closesocket(client_socket);
    closesocket(server_fd);
#else
    close(client_socket);
    close(server_fd);
#endif
    EVP_PKEY_free(pkey);
    cleanupWinsock();
    return 0;
}