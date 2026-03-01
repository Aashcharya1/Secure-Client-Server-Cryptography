#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <chrono>
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
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

const int PORT = 8080;
const int BUFFER_SIZE = 4096;
const char* SERVER_IP = "127.0.0.1";

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

KeyIV performDHKeyExchange(int sock) {
    // 1. Receive P parameter
    uint32_t net_p_len;
    recvAll(sock, (char*)&net_p_len, sizeof(net_p_len));
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

    const BIGNUM *pub_key, *priv_key;
    DH_get0_key(dh, &pub_key, &priv_key);

    char* pub_hex = BN_bn2hex(pub_key);
    char* priv_hex = BN_bn2hex(priv_key);
    std::cout << "--- DH Key Generation ---" << std::endl;
    std::cout << "Sender Private Key: " << priv_hex << std::endl;
    std::cout << "Sender Public Key:  " << pub_hex << std::endl << std::endl;
    OPENSSL_free(pub_hex);
    OPENSSL_free(priv_hex);

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

    BN_free(receiver_pub_key);
    DH_free(dh);

    std::cout << "Diffie-Hellman key exchange completed successfully.\n" << std::endl;
    return {aes_key, iv};
}

std::vector<unsigned char> encryptAES(const std::vector<unsigned char>& plaintext,
                                      const std::vector<unsigned char>& key,
                                      const std::vector<unsigned char>& iv) {
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

void sendMessage(int sock, const std::string& message, const std::vector<unsigned char>& aes_key, const std::vector<unsigned char>& iv) {
    std::string command = "MSG:" + message;
    std::vector<unsigned char> plaintext(command.begin(), command.end());
    
    // Rubric Requirement: Print plaintext and encrypted text
    std::cout << "--- Outgoing Message ---" << std::endl;
    std::cout << "Original Plaintext: " << command << std::endl;
    
    std::vector<unsigned char> encrypted = encryptAES(plaintext, aes_key, iv);
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

void sendFile(int sock, const std::string& filename, const std::vector<unsigned char>& aes_key, const std::vector<unsigned char>& iv) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return;
    
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> file_data(file_size);
    file.read((char*)file_data.data(), file_size);
    file.close();
    
    std::string command = "FILE NAME:" + filename + " SIZE:" + std::to_string(file_size) + "\n";
    std::vector<unsigned char> command_bytes(command.begin(), command.end());
    
    std::vector<unsigned char> encrypted_command = encryptAES(command_bytes, aes_key, iv);
    uint32_t cmd_len = htonl(encrypted_command.size());
    send(sock, (char*)&cmd_len, sizeof(cmd_len), 0);
    send(sock, (char*)encrypted_command.data(), encrypted_command.size(), 0);
    
    std::vector<unsigned char> encrypted_file = encryptAES(file_data, aes_key, iv);
    
    uint32_t file_encrypted_len = htonl(encrypted_file.size());
    send(sock, (char*)&file_encrypted_len, sizeof(file_encrypted_len), 0);
    send(sock, (char*)encrypted_file.data(), encrypted_file.size(), 0);
    
    std::cout << "\nFile encrypted and sent: " << filename << " (" << file_size << " bytes)" << std::endl;
    
    uint32_t ack_len;
    recvAll(sock, (char*)&ack_len, sizeof(ack_len));
    ack_len = ntohl(ack_len);
    
    char buffer[BUFFER_SIZE] = {0};
    recvAll(sock, buffer, ack_len);
    std::cout << "Server Response: " << std::string(buffer, ack_len) << std::endl;
}

int main(int argc, char* argv[]) {
    initializeWinsock();
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);
    
    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    std::cout << "Connected to receiver\n" << std::endl;
    
    KeyIV keyiv = performDHKeyExchange(sock);
    
    if (argc > 1) {
        std::string command = argv[1];
        if (command == "msg" && argc > 2) {
            sendMessage(sock, argv[2], keyiv.key, keyiv.iv);
        }
        else if (command == "file" && argc > 2) {
            sendFile(sock, argv[2], keyiv.key, keyiv.iv);
        }
    } else {
        std::cout << "Usage: sender_b msg <message> or sender_b file <filename>" << std::endl;
        while (true) {
            std::cout << "\nEnter command (msg/file/exit): ";
            std::string cmd;
            std::cin >> cmd;
            
            if (cmd == "msg") {
                std::cout << "Enter message: ";
                std::string msg;
                std::cin.ignore();
                std::getline(std::cin, msg);
                sendMessage(sock, msg, keyiv.key, keyiv.iv);
            }
            else if (cmd == "file") {
                std::cout << "Enter filename: ";
                std::string filename;
                std::cin >> filename;
                sendFile(sock, filename, keyiv.key, keyiv.iv);
            }
            else if (cmd == "exit" || cmd == "EXIT") {
                break;
            }
        }
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
    cleanupWinsock();
    return 0;
}