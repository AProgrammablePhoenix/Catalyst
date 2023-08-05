#include <iostream>
#include <string>
#include <bit>
#include <cmath>
#include <thread>
#include <array>
#include <vector>

#include "catalyst_internal.hpp"
#include "../catalyst.hpp"

using namespace catalyst::constants;

namespace {
    void stage1(catalyst::state& state) {
        const std::vector<uint32_t>& constants_set = state.s1_constants;
        const size_t n_constants = constants_set.size() * sizeof(uint32_t);

        std::vector<uint8_t> cipher;

        for (uint64_t i = 0; i < state.plain.size(); ++i) {
            cipher.push_back(state.plain[i] + ((uint8_t*)constants_set.data())[i % n_constants]);
        }

        state.cipher = cipher;
    }
    void Istage1(catalyst::state& state) {
        const std::vector<uint32_t>& constants_set = state.s1_constants;
        const size_t n_constants = constants_set.size() * sizeof(uint32_t);
        std::vector<uint8_t> plain;

        for (uint64_t i = 0; i < state.cipher.size(); ++i) {
            plain.push_back(state.cipher[i] - ((uint8_t*)constants_set.data())[i % n_constants]);
        }

        state.plain = plain;
    }

    void stage2(catalyst::state& state) {
        const std::array<uint32_t, 32>& constants_set = state.s2_constants;
        uint32_t(*const sigma)(uint32_t) = state.s2_transform;

        auto& cipher = state.cipher;

        size_t i = 0;
        for (; i < cipher.size() / sizeof(uint32_t); ++i) {
            uint32_t* const ptr = (uint32_t*)&cipher[i * sizeof(uint32_t)];

            if constexpr (std::endian::native == std::endian::little) {
                *ptr = std::byteswap(*ptr);
            }

            *ptr = sigma(*ptr + constants_set[i % 32]);
        }
        for (i *= sizeof(uint32_t); i < cipher.size(); ++i) {
            cipher[i] += (uint8_t)sigma(constants_set[i % 32]);
        }
    }
    void Istage2(catalyst::state& state) {
        const std::array<uint32_t, 32>& constants_set = state.s2_constants;
        uint32_t(*const sigma)(uint32_t) = state.s2_transform;
        uint32_t(*const Isigma)(uint32_t) = state.s2_Itransform;

        auto& cipher = state.cipher;
        
        size_t i = 0;
        for (i = 0; i < cipher.size() / sizeof(uint32_t); ++i) {
            uint32_t* ptr = (uint32_t*)&cipher[i * sizeof(uint32_t)];
            *ptr = Isigma(*ptr);
            *ptr -= constants_set[i % 32];

            if constexpr (std::endian::native == std::endian::little) {
                *ptr = std::byteswap(*ptr);
            }
        }
        for (i *= sizeof(uint32_t); i < cipher.size(); ++i) {
            cipher[i] -= (uint8_t)sigma(constants_set[i % 32]);
        }
    }

    void stage3(catalyst::state& state) {
        const bmp::cpp_int& key_n = state.key_n;
        const size_t n_rounds = state.n_rounds;
        const size_t rounds = 1 + std::ceil(std::log2(n_rounds));

        const std::array<uint8_t, catalyst::SBox::sbox_size>& sbox = state.s3_sbox;
        const std::array<uint8_t, catalyst::SBox::sbox_size>& transform_v = state.s3_transform_data;

        auto& cipher = state.cipher;

        for (size_t i = 0; i < rounds; ++i) {
            for (auto& e : cipher) {
                e = sbox[e];
            }
            std::rotate(cipher.begin(), cipher.begin() + 1, cipher.end());
        }        
        for (size_t i = 0; i < cipher.size(); ++i) {
            cipher[i] += transform_v[i % catalyst::SBox::sbox_size];
        }
    }
    void Istage3(catalyst::state& state) {
        const std::array<uint8_t, catalyst::SBox::sbox_size>& Isbox = state.s3_Isbox;
        const std::array<uint8_t, catalyst::SBox::sbox_size>& transform_v = state.s3_transform_data;

        auto& cipher = state.cipher;

        for (size_t i = 0; i < cipher.size(); ++i) {
            cipher[i] -= transform_v[i % catalyst::SBox::sbox_size];
        }
        
        const bmp::cpp_int& key_n = state.key_n;
        const size_t n_rounds = state.n_rounds;
        const size_t rounds = 1 + std::ceil(std::log2(n_rounds));        

        for (size_t i = 0; i < rounds; ++i) {
            for (auto& e : cipher) {
                e = Isbox[e];
            }
            std::rotate(cipher.rbegin(), cipher.rbegin() + 1, cipher.rend());
        }
    }

    void stage4(catalyst::state& state) {
        const std::vector<uint8_t>& extension = state.s4_random_bytes;
        state.cipher.insert(state.cipher.end(), extension.cbegin(), extension.cend());
    }
    void Istage4(catalyst::state& state) {
        const uint8_t extension_size = state.cipher.back();
        state.cipher.resize(state.cipher.size() - extension_size - 1);
    }

    // involution (apply it on the resulting cipher to get its state before the transformation)
    void stage5(catalyst::state& state) {
        const size_t n = state.cipher.size();

        const std::vector<uint8_t> xor_transform = state.s5_transform_data;
        for (size_t i = 0; i < n; ++i) {
            state.cipher[i] ^= xor_transform[i];
        }
    }

    catalyst::state get_state_encryption(uint8_t plain_data[], size_t plain_length, uint8_t key_data[], size_t key_length) {
        catalyst::state state;

        state.plain = std::vector<uint8_t>(plain_data, plain_data + plain_length);

        state.s1_constants = extend_constants(get_constants_set(key_data, key_length), plain_length);

        state.s2_constants = sigma::get_constants_set(key_data, key_length);
        state.s2_transform = catalyst::sigmas::get_sigma(key_data, key_length);
        state.s2_Itransform = catalyst::sigmas::get_Isigma(key_data, key_length);

        state.s3_sbox = catalyst::SBox::get_sbox();
        state.s3_Isbox = catalyst::SBox::get_inverse_sbox();
        state.s3_transform_data = catalyst::SBox::get_transform(key_data, key_length);

        state.s4_random_bytes = catalyst::Extend::generate(plain_length, key_length);

        state.s5_transform_data = catalyst::Xor::generate_transform(key_data, key_length, plain_length + state.s4_random_bytes.size());

        state.key_n = catalyst::helper::bytes_to_int(
            std::vector<uint8_t>(
                key_data,
                key_data + key_length
            )
        );
        state.n_rounds = catalyst::helper::get_rounds(state.key_n);

        return state;
    }
    catalyst::state get_partial_state_decryption(uint8_t cipher_data[], size_t cipher_length, uint8_t key_data[], size_t key_length) {
        catalyst::state state;

        state.cipher = std::vector<uint8_t>(cipher_data, cipher_data + cipher_length);

        state.s2_constants = sigma::get_constants_set(key_data, key_length);
        state.s2_transform = catalyst::sigmas::get_sigma(key_data, key_length);
        state.s2_Itransform = catalyst::sigmas::get_Isigma(key_data, key_length);

        state.s3_sbox = catalyst::SBox::get_sbox();
        state.s3_Isbox = catalyst::SBox::get_inverse_sbox();
        state.s3_transform_data = catalyst::SBox::get_transform(key_data, key_length);

        state.s5_transform_data = catalyst::Xor::generate_transform(key_data, key_length, cipher_length);

        state.key_n = catalyst::helper::bytes_to_int(
            std::vector<uint8_t>(
                key_data,
                key_data + key_length
            )
        );
        state.n_rounds = catalyst::helper::get_rounds(state.key_n);

        return state;
    }
}

std::vector<uint8_t> catalyst::encrypt(uint8_t plain_data[], size_t plain_length, uint8_t key_data[], size_t key_length) {
    catalyst::state state = get_state_encryption(plain_data, plain_length, key_data, key_length);
    
    stage1(state);
    stage2(state);
    stage3(state);
    stage4(state);
    stage5(state);

    return state.cipher;
}
std::vector<uint8_t> catalyst::decrypt(uint8_t cipher_data[], size_t cipher_length, uint8_t key_data[], size_t key_length) {
    catalyst::state state = get_partial_state_decryption(cipher_data, cipher_length, key_data, key_length);

    stage5(state);
    Istage4(state);

    state.s1_constants = extend_constants(get_constants_set(key_data, key_length), state.cipher.size());

    Istage3(state);
    Istage2(state);
    Istage1(state);

    return state.plain;
}
std::vector<uint8_t> catalyst::encrypt(const catalyst::input_data& data) {
    return catalyst::encrypt(data.data, data.data_length, data.key, data.key_length);
}
std::vector<uint8_t> catalyst::decrypt(const catalyst::input_data& data) {
    return catalyst::decrypt(data.data, data.data_length, data.key, data.key_length);
}

std::vector<std::vector<uint8_t>> catalyst::encrypt_serial(const std::vector<catalyst::input_data>& data_v) {
    const size_t n = data_v.size();    
    std::vector<std::vector<uint8_t>> result(n);

    for (size_t i = 0; i < n; ++i) {
        result[i] = encrypt(data_v[i]);
    }

    return result;
}
std::vector<std::vector<uint8_t>> catalyst::decrypt_serial(const std::vector<catalyst::input_data>& data_v) {
    const size_t n = data_v.size();    
    std::vector<std::vector<uint8_t>> result(n);

    for (size_t i = 0; i < n; ++i) {
        result[i] = decrypt(data_v[i]);
    }

    return result;
}
std::vector<std::vector<uint8_t>> catalyst::encrypt_serial_mt(const std::vector<catalyst::input_data>& data_v, const size_t n_block) {
    const size_t n = data_v.size();
    std::vector<std::vector<uint8_t>> result(n);
    std::vector<std::thread> threads;
    
    for (size_t i = 0; i < n_block && i * n_block < n; ++i) {
        threads.emplace_back([](const size_t i, const size_t n, const size_t n_block, const std::vector<catalyst::input_data>* const data_v, std::vector<uint8_t>* const out) {
            for (size_t j = 0; j < n_block && j + i * n_block < n; ++j) {
                *(out + j) = encrypt((*data_v)[j + i * n_block]);
            }
        }, i, n, n_block, &data_v, result.data() + n_block * i);
    }

    for (auto& t : threads) {
        t.join();
    }

    return result;
}
std::vector<std::vector<uint8_t>> catalyst::decrypt_serial_mt(const std::vector<catalyst::input_data>& data_v, const size_t n_block) {
    const size_t n = data_v.size();
    std::vector<std::vector<uint8_t>> result(n);
    std::vector<std::thread> threads;
    
    for (size_t i = 0; i < n_block && i * n_block < n; ++i) {
        threads.emplace_back([](const size_t i, const size_t n, const size_t n_block, const std::vector<catalyst::input_data>* const data_v, std::vector<uint8_t>* const out) {
            for (size_t j = 0; j < n_block && j + i * n_block < n; ++j) {
                *(out + j) = decrypt((*data_v)[j + i * n_block]);
            }
        }, i, n, n_block, &data_v, result.data() + n_block * i);
    }

    for (auto& t : threads) {
        t.join();
    }

    return result;
}