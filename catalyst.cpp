#include <iostream>
#include <filesystem>
#include <fstream>
#include <unordered_set>
#include <vector>

#include "catalyst.hpp"
#include "commandline_args.hpp"

inline void print_vector(const std::vector<uint8_t>& data) {    
    printf("\t(string) ");
    for (const auto& e : data) {
        printf("%c", (char)e);
    }
    printf("\n");
    
    printf("\t(hexadecimal) 0x");
    for (const auto& e : data) {
        printf("%02x", (uint16_t)e);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    _execution_context ectx = process_arguments(argc, argv);

    const std::string& data = ectx.data;
    const std::string& key = ectx.key;

    std::cout << "\n";
    std::cout << "provided key:\n";
    print_vector(std::vector<uint8_t>((uint8_t*)key.data(), (uint8_t*)key.data() + key.size()));
    std::cout << std::endl;

    if (ectx.mode == _internal_mode::encryption) {
        std::cout << "mode: encryption\n\n";
        std::cout << "input data:\n";
        
        std::vector<uint8_t> raw_data((uint8_t*)data.data(), (uint8_t*)data.data() + data.size());

        print_vector(raw_data);
        std::cout << std::endl;
        
        std::vector<uint8_t> cipher = catalyst::encrypt(raw_data.data(), raw_data.size(), (uint8_t*)key.data(), key.size());
        std::cout << "output cipher:\n";
        if (!ectx.output_to_file) {
            print_vector(cipher);
        }
        else {
            std::ofstream output_f(ectx.output_file_name, std::ios::binary);
            if (output_f) {
                output_f.write((char*)cipher.data(), cipher.size() / sizeof(char));
                std::cout << "Output written to file: " << ectx.output_file_name << std::endl;
            }
            else {
                std::cerr << "Unable to write output to file: " << ectx.output_file_name << std::endl;
                return -1;
            }
        }
    } else if (ectx.mode == _internal_mode::decryption) {
        std::cout << "mode: decryption\n\n";
        std::cout << "input data:\n";

        std::vector<uint8_t> raw_data((uint8_t*)data.data(), (uint8_t*)data.data() + data.size());

        print_vector(raw_data);
        std::cout << std::endl;

        std::vector<uint8_t> recovered = catalyst::decrypt((uint8_t*)data.data(), data.size(), (uint8_t*)key.data(), key.size());
        std::cout << "recovered data:\n";
        if (!ectx.output_to_file) {
            print_vector(recovered);
        }
        else {
            std::ofstream output_f(ectx.output_file_name, std::ios::binary);
            if (output_f) {
                output_f.write((char*)recovered.data(), recovered.size() / sizeof(char));
                std::cout << "Output written to file: " << ectx.output_file_name << std::endl;
            }
            else {
                std::cerr << "Unable to write output to file: " << ectx.output_file_name << std::endl;
                return -1;
            }
        }
    }

    return 0;
}