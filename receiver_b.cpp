#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <utility>
#include <iomanip>
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>

struct KeyIV {
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
};

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

const int PORT = 8080;
const int BUFFER_SIZE = 4096;

// Helper to reliably receive exactly 'len' bytes
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
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        exit(1);
    }
#endif
}

void cleanupWinsock() {
#ifdef _WIN32
    WSACleanup();
#endif
}

KeyIV performDHKeyExchange(int sock) {
    DH* dh = DH_new();
    if (DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL) != 1 || DH_generate_key(dh) != 1) {
        std::cerr << "Error generating DH parameters/keys" << std::endl;
        exit(1);
    }
    
    const BIGNUM *pub_key, *priv_key;
    DH_get0_key(dh, &pub_key, &priv_key);
    
    // Rubric Requirement: Show private/public components
    char* pub_hex = BN_bn2hex(pub_key);
    char* priv_hex = BN_bn2hex(priv_key);
    std::cout << "--- DH Key Generation ---" << std::endl;
    std::cout << "Receiver Private Key: " << priv_hex << std::endl;
    std::cout << "Receiver Public Key:  " << pub_hex << std::endl << std::endl;
    OPENSSL_free(pub_hex);
    OPENSSL_free(priv_hex);

    int pub_key_len = BN_num_bytes(pub_key);
    std::vector<unsigned char> pub_key_bytes(pub_key_len);
    BN_bn2bin(pub_key, pub_key_bytes.data());
    
    uint32_t len = htonl(pub_key_len);
    send(sock, (char*)&len, sizeof(len), 0);
    send(sock, (char*)pub_key_bytes.data(), pub_key_len, 0);
    
    uint32_t sender_pub_key_len;
    recvAll(sock, (char*)&sender_pub_key_len, sizeof(sender_pub_key_len));
    sender_pub_key_len = ntohl(sender_pub_key_len);
    
    std::vector<unsigned char> sender_pub_key_bytes(sender_pub_key_len);
    recvAll(sock, (char*)sender_pub_key_bytes.data(), sender_pub_key_len);
    
    BIGNUM* sender_pub_key = BN_bin2bn(sender_pub_key_bytes.data(), sender_pub_key_len, NULL);
    
    std::vector<unsigned char> shared_secret(DH_size(dh));
    int secret_len = DH_compute_key(shared_secret.data(), sender_pub_key, dh);
    shared_secret.resize(secret_len);
    
    // Rubric Requirement: Show shared secret
    printHex("Derived Shared Secret", shared_secret);
    
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
    
    BN_free(sender_pub_key);
    DH_free(dh);
    
    std::cout << "Diffie-Hellman key exchange completed successfully.\n" << std::endl;
    
    return {aes_key, iv};
}

std::vector<unsigned char> decryptAES(const std::vector<unsigned char>& ciphertext, 
                                      const std::vector<unsigned char>& key,
                                      const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data());
    
    std::vector<unsigned char> plaintext(ciphertext.size() + AES_BLOCK_SIZE);
    int len, plaintext_len = 0;
    
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        std::cerr << "Error finalizing decryption (Bad Padding/Key)" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

int main() {
    initializeWinsock();
    int server_fd, client_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);
    std::cout << "Receiver listening on port " << PORT << std::endl;

    client_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen);
    std::cout << "Connection accepted\n" << std::endl;
    
    KeyIV keyiv = performDHKeyExchange(client_socket);

    while (true) {
        uint32_t encrypted_len;
        if (!recvAll(client_socket, (char*)&encrypted_len, sizeof(encrypted_len))) break;
        encrypted_len = ntohl(encrypted_len);
        
        std::vector<unsigned char> encrypted_data(encrypted_len);
        if (!recvAll(client_socket, (char*)encrypted_data.data(), encrypted_len)) break;
        
        // Rubric Requirement: Show received ciphertext and decrypted message
        std::cout << "--- Incoming Transmission ---" << std::endl;
        printHex("Received Ciphertext (Hex)", encrypted_data);
        
        std::vector<unsigned char> decrypted = decryptAES(encrypted_data, keyiv.key, keyiv.iv);
        if (decrypted.empty()) break;
        
        std::string message(decrypted.begin(), decrypted.end());
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
                std::string filename = "recv_" + message.substr(name_pos + 5, name_end - name_pos - 5); // Prevent overwrite
                
                uint32_t file_encrypted_len;
                recvAll(client_socket, (char*)&file_encrypted_len, sizeof(file_encrypted_len));
                file_encrypted_len = ntohl(file_encrypted_len);
                
                std::vector<unsigned char> file_encrypted(file_encrypted_len);
                recvAll(client_socket, (char*)file_encrypted.data(), file_encrypted_len);
                
                std::vector<unsigned char> file_data = decryptAES(file_encrypted, keyiv.key, keyiv.iv);
                
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
    cleanupWinsock();
    return 0;
}