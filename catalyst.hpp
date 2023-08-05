#pragma once

#include <iostream>
#include <cmath>
#include <cstdint>
#include <array>
#include <vector>

namespace catalyst {
    struct input_data {
        size_t data_length;
        uint8_t* data;
        size_t key_length;
        uint8_t* key;
    };
    
    // encrypts <plain_data> of length <plain_length> into a cipher of random length (>= plain_length),
    // using <key_data> of length <key_length>
    std::vector<uint8_t> encrypt(uint8_t plain_data[], size_t plain_length, uint8_t key_data[], size_t key_length);
    // decrypts <plain_data> of length <plain_length> into a cipher of random length (>= plain_length),
    // using <key_data> of length <key_length>
    std::vector<uint8_t> decrypt(uint8_t cipher_data[], size_t cipher_length, uint8_t key_data[], size_t key_length);
    // encrypts data according to the data stored in the struct <data>
    std::vector<uint8_t> encrypt(const input_data& data);
    // decrypts data according to the data stored in the struct <data>
    std::vector<uint8_t> decrypt(const input_data& data);

    // encrypts a vector of data, iteratively calling catalyst::encrypt(data_v[i])
    std::vector<std::vector<uint8_t>> encrypt_serial(const std::vector<input_data>& data_v);
    // decrypts a vector of data, iteratively calling catalyst::decrypt(data_v[i])
    std::vector<std::vector<uint8_t>> decrypt_serial(const std::vector<input_data>& data_v);

    // multithreaded equivalent of catalyst::encrypt_serial, n_block is the number of iterations done each thread
    std::vector<std::vector<uint8_t>> encrypt_serial_mt(const std::vector<input_data>& data_v, const size_t n_block = 1);
    // multithreaded equivalent of catalyst::decrypt_serial, n_block is the number of iterations done each thread
    std::vector<std::vector<uint8_t>> decrypt_serial_mt(const std::vector<input_data>& data_v, const size_t n_block = 1);
}