#include <iostream>
#include <fstream>
#include <random>

int main() {
    const size_t file_size = 1024; // 1KB
    const std::string filename = "test_1kb.bin";
    
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error creating test file" << std::endl;
        return 1;
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned char> dis(0, 255);
    
    for (size_t i = 0; i < file_size; i++) {
        file.put(dis(gen));
    }
    
    file.close();
    std::cout << "Generated test file: " << filename << " (" << file_size << " bytes)" << std::endl;
    
    return 0;
}
