#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_set>
#include <vector>

#include "commandline_args.hpp"

namespace {
    static const std::unordered_set<std::string> valid_modes = {
        "-e", "-ex", "-ef", "-exf",
        "-d", "-dx", "-df", "dxf"
    };
    static const std::vector<std::pair<std::string, std::string>> modes_help = {
        { "-e  ",   "encrypts data with specified key, data and key are both strings" },
        { "-ex ",  "encrypts data with specified key, data and key are both in hexadecimal" },
        { "-ef ",  "encrypts file with specified key, data is the name of the file to encrypt, key is a string" },
        { "-exf", "encrypts file with specified key, data is the name of the file to encrypt, key in hexadecimal" },
        
        { "-d  ",   "decrypts data with specified key, data and key are both strings" },
        { "-dx ",  "decrypts data with specified key, data and key are both in hexadecimal" },
        { "-df ",  "decrypts file with specified key, data is the name of the file to decrypt, key is a string" },
        { "-dxf", "decrypts file with specified key, data is the name of the file to decrypt, key in hexadecimal" }
    };
    [[noreturn]] static void print_usage() {
        static const std::string str = "\nUsage: catalyst <-e[x][f]|-d[x][f]> <data> <key>\n";
        std::string msg = str;
        for (const auto& m : modes_help) {
            msg += m.first + ":" + m.second + "\n";
        }
        throw std::runtime_error(msg);
    }

    static std::string parse_hex(const std::string& s) {
        std::string parsed = "";
        char temp[3] = { 0 };
        char* temp_end = nullptr;

        for (size_t i = 2; i < s.size(); i += 2) {
            temp[0] = s[i];
            temp[1] = s[i + 1];
            char c = (char)(uint8_t)std::strtoul(temp, &temp_end, 16);
            parsed += c;
        }

        return parsed;
    }
    static std::string read_file(const std::string filename) {
        std::string read = "";

        const size_t filesize = std::filesystem::file_size(filename);
        std::ifstream input_data_file(filename, std::ios::binary);

        if (input_data_file) {
            read.resize(filesize);
            input_data_file.read((char*)read.data(), filesize);
            return read;
        }
        else {
            throw std::runtime_error("Unable to read file: " + filename);
        }
    }
}

_execution_context process_arguments(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
    }

    _execution_context ectx;

    std::string mode = argv[1];
    if (!valid_modes.contains(mode)) {
        print_usage();
    }
    mode = mode.substr(1);

    if (argc != 4) {
        print_usage();
    }

    if (mode.ends_with("x")) {
        mode = mode.substr(0, mode.size() - 1);
        std::string _data = argv[2];
        std::string _key = argv[3];

        ectx.data = parse_hex(_data);
        ectx.key = parse_hex(_key);
    }
    else if (mode.ends_with("f")) {
        mode = mode.substr(0, mode.size() - 1);
        ectx.output_to_file = true;

        auto output_path = std::filesystem::path(argv[2]);
        output_path.replace_extension(".out");
        ectx.output_file_name = output_path.string();
        
        ectx.data = read_file(argv[2]);
        
        if (mode.ends_with("x")) {
            mode = mode.substr(0, mode.size() - 1);
            ectx.key = parse_hex(argv[3]);
        }
        else {
            ectx.key = argv[3];
        }
    }
    else {
        ectx.data = argv[2];
        ectx.key = argv[3];
    }

    if (mode == "e") {
        ectx.mode = _internal_mode::encryption;
    }
    else {
        ectx.mode = _internal_mode::decryption;
    }

    return ectx;
}