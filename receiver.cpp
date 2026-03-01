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
typedef int socklen_t; // Windows compatibility fix
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

const int PORT = 8080;
const int BUFFER_SIZE = 4096;

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

int main() {
    initializeWinsock();
    
    int server_fd, client_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        std::cerr << "Socket creation failed" << std::endl;
        cleanupWinsock();
        exit(1);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) < 0) {
        std::cerr << "setsockopt failed" << std::endl;
        cleanupWinsock();
        exit(1);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        std::cerr << "Bind failed" << std::endl;
        cleanupWinsock();
        exit(1);
    }

    if (listen(server_fd, 3) < 0) {
        std::cerr << "Listen failed" << std::endl;
        cleanupWinsock();
        exit(1);
    }

    std::cout << "Receiver listening on port " << PORT << std::endl;

    if ((client_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0) {
        std::cerr << "Accept failed" << std::endl;
        cleanupWinsock();
        exit(1);
    }

    std::cout << "Connection accepted" << std::endl;

    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int valread = recv(client_socket, buffer, BUFFER_SIZE, 0);
        
        if (valread <= 0) {
            std::cout << "Connection closed" << std::endl;
            break;
        }

        // Safely construct string using only the bytes read
        std::string command(buffer, valread);
        
        if (command.length() >= 4 && command.substr(0, 4) == "MSG:") {
            std::string message = command.substr(4);
            std::cout << "Received message: " << message << std::endl;
            
            std::string ack = "ACK: Message received";
            send(client_socket, ack.c_str(), ack.length(), 0);
        }
        else if (command.length() >= 4 && command.substr(0, 4) == "FILE") {
            std::string filename;
            size_t file_size = 0;
            
            size_t name_pos = command.find("NAME:");
            size_t size_pos = command.find("SIZE:");
            
            if (name_pos != std::string::npos && size_pos != std::string::npos) {
                size_t name_end = command.find(" ", name_pos + 5);
                filename = command.substr(name_pos + 5, name_end - name_pos - 5);
                
                size_t size_end = command.find("\n", size_pos + 5);
                file_size = std::stoul(command.substr(size_pos + 5, size_end - size_pos - 5));
                
                std::cout << "Receiving file: " << filename << " (" << file_size << " bytes)" << std::endl;
                
                std::string ready = "READY";
                send(client_socket, ready.c_str(), ready.length(), 0);
                
                std::ofstream outfile(filename, std::ios::binary);
                size_t total_received = 0;
                
                while (total_received < file_size) {
                    memset(buffer, 0, BUFFER_SIZE);
                    // Critical fix: Only read up to the remaining file size
                    size_t bytes_to_read = std::min((size_t)BUFFER_SIZE, file_size - total_received);
                    int bytes_received = recv(client_socket, buffer, bytes_to_read, 0);
                    
                    if (bytes_received <= 0) break;
                    
                    outfile.write(buffer, bytes_received);
                    total_received += bytes_received;
                }
                
                outfile.close();
                std::cout << "File received successfully: " << filename << std::endl;
                
                std::string ack = "ACK: File received";
                send(client_socket, ack.c_str(), ack.length(), 0);
            }
        }
        else if (command == "EXIT") {
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