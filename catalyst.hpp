#pragma once

#include <iostream>
#include <cmath>
#include <cstdint>
#include <array>
#include <vector>

#include <boost/multiprecision/cpp_int.hpp>

namespace bmp = boost::multiprecision;

namespace catalyst {
    struct input_data {
        size_t data_length;
        uint8_t* data;
        size_t key_length;
        uint8_t* key;
    };

    namespace helper {
        bmp::cpp_int bytes_to_int(const std::vector<uint8_t>& data);
        std::vector<uint64_t> generate_prime_numbers(const uint64_t& n);
        uint64_t get_rounds(const bmp::cpp_int& key);
    };
    namespace constants {
        namespace sigma {
            std::array<uint32_t, 32> get_constants_1();
            std::array<uint32_t, 32> get_constants_2();
            std::array<uint32_t, 32> get_constants_3();
            std::array<uint32_t, 32> get_constants_4();
            const std::array<uint32_t, 32>& get_constants_set(uint8_t key_data[], uint64_t length);

            inline const std::array<std::array<uint32_t, 32>, 4>& constants = { get_constants_1(), get_constants_2(), get_constants_3(), get_constants_4() };
        }

        std::vector<uint32_t> get_constants_1();
        std::vector<uint32_t> get_constants_2();
        std::vector<uint32_t> get_constants_3();
        std::vector<uint32_t> get_constants_4();
        std::vector<uint32_t> extend_constants(const std::vector<uint32_t>& constants, uint64_t length);
        const std::vector<uint32_t>& get_constants_set(uint8_t key_data[], uint64_t length);

        inline const std::array<std::vector<uint32_t>, 4> constants = { get_constants_1(), get_constants_2(), get_constants_3(), get_constants_4() };
    }
    namespace sigmas {
        uint32_t sigma0(uint32_t x);
        uint32_t sigma1(uint32_t x);
        uint32_t Sigma0(uint32_t x);
        uint32_t Sigma1(uint32_t x);

        uint32_t Isigma0(uint32_t x);
        uint32_t Isigma1(uint32_t x);
        uint32_t ISigma0(uint32_t x);
        uint32_t ISigma1(uint32_t x);

        uint32_t(*get_sigma(uint8_t key_data[], uint64_t length))(uint32_t);
        uint32_t(*get_Isigma(uint8_t key_data[], uint64_t length))(uint32_t);

        inline const std::array<uint32_t(*)(uint32_t), 4> sigmas = { &sigma0, &sigma1, &Sigma0, &Sigma1 };
        inline const std::array<uint32_t(*)(uint32_t), 4> Isigmas = { &Isigma0, &Isigma1, &ISigma0, &ISigma1 };
    }
    namespace SBox {
        constexpr size_t sbox_size = 256;

        const std::array<uint8_t, sbox_size>& get_sbox();
        const std::array<uint8_t, sbox_size>& get_inverse_sbox();

        std::array<uint8_t, sbox_size> get_transform(uint8_t key_data[], uint64_t length);
    }
    namespace Extend {
        std::vector<uint8_t> generate(uint64_t cipher_length, uint64_t key_length);
    }
    namespace Xor {
        std::vector<uint8_t> generate_transform(uint8_t key_data[], uint64_t length, uint64_t n);
    }

    struct state {
        std::vector<uint32_t> s1_constants;

        std::array<uint32_t, 32> s2_constants;
        uint32_t(*s2_transform)(uint32_t);
        uint32_t(*s2_Itransform)(uint32_t);

        std::array<uint8_t, SBox::sbox_size> s3_sbox;
        std::array<uint8_t, SBox::sbox_size> s3_Isbox;
        std::array<uint8_t, SBox::sbox_size> s3_transform_data;

        std::vector<uint8_t> s4_random_bytes;

        std::vector<uint8_t> s5_transform_data;

        bmp::cpp_int key_n;
        size_t n_rounds;

        std::vector<uint8_t> plain;
        std::vector<uint8_t> cipher;
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