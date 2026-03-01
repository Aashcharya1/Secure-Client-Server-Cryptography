#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

const int PORT = 8080;
const int BUFFER_SIZE = 4096;
const char* SERVER_IP = "127.0.0.1";

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

void sendMessage(int sock, const std::string& message) {
    std::string command = "MSG:" + message;
    send(sock, command.c_str(), command.length(), 0);
    
    char buffer[BUFFER_SIZE] = {0};
    int valread = recv(sock, buffer, BUFFER_SIZE, 0);
    if (valread > 0) {
        std::cout << "Response: " << std::string(buffer, valread) << std::endl;
    }
}

void sendFile(int sock, const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file " << filename << std::endl;
        return;
    }
    
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::string command = "FILE NAME:" + filename + " SIZE:" + std::to_string(file_size) + "\n";
    send(sock, command.c_str(), command.length(), 0);
    
    char buffer[BUFFER_SIZE] = {0};
    int valread = recv(sock, buffer, BUFFER_SIZE, 0);
    if (valread <= 0 || std::string(buffer, valread) != "READY") {
        std::cerr << "Error: Receiver not ready" << std::endl;
        file.close();
        return;
    }
    
    std::vector<char> file_data(file_size);
    file.read(file_data.data(), file_size);
    file.close();
    
    size_t total_sent = 0;
    while (total_sent < file_size) {
        size_t to_send = std::min((size_t)BUFFER_SIZE, file_size - total_sent);
        int bytes_sent = send(sock, file_data.data() + total_sent, to_send, 0);
        if (bytes_sent <= 0) {
            std::cerr << "Error sending file data" << std::endl;
            return;
        }
        total_sent += bytes_sent;
    }
    
    std::cout << "File sent: " << filename << " (" << file_size << " bytes)" << std::endl;
    
    memset(buffer, 0, BUFFER_SIZE);
    valread = recv(sock, buffer, BUFFER_SIZE, 0);
    if (valread > 0) {
        std::cout << "Response: " << std::string(buffer, valread) << std::endl;
    }
}

int main(int argc, char* argv[]) {
    initializeWinsock();
    
    int sock = 0;
    struct sockaddr_in serv_addr;
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        cleanupWinsock();
        return 1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/Address not supported" << std::endl;
        cleanupWinsock();
        return 1;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        cleanupWinsock();
        return 1;
    }
    
    std::cout << "Connected to receiver" << std::endl;
    
    if (argc > 1) {
        std::string command = argv[1];
        if (command == "msg" && argc > 2) {
            sendMessage(sock, argv[2]);
        }
        else if (command == "file" && argc > 2) {
            sendFile(sock, argv[2]);
        }
    } else {
        std::cout << "Usage: sender msg <message> or sender file <filename>" << std::endl;
        std::cout << "Enter command (msg/file/exit): ";
        std::string cmd;
        std::cin >> cmd;
        
        if (cmd == "msg") {
            std::cout << "Enter message: ";
            std::string msg;
            std::cin.ignore();
            std::getline(std::cin, msg);
            sendMessage(sock, msg);
        }
        else if (cmd == "file") {
            std::cout << "Enter filename: ";
            std::string filename;
            std::cin >> filename;
            sendFile(sock, filename);
        }
    }
    
    std::string exit_cmd = "EXIT";
    send(sock, exit_cmd.c_str(), exit_cmd.length(), 0);
    
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    
    cleanupWinsock();
    return 0;
}