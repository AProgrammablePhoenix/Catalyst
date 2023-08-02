#pragma once

#include <iostream>
#include <string>

enum class _internal_mode {
    encryption, // encrypts data
    decryption, // decrypts data
};

struct _execution_context {
    _internal_mode mode;
    bool output_to_file = false;
    std::string output_file_name;

    std::string data;
    std::string key;
};

_execution_context process_arguments(int argc, char** argv);
