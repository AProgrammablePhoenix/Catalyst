#include <iostream>
#include <vector>

#include "catalyst_internal.hpp"
#include "../sha3/sha3.hpp"

std::vector<uint8_t> catalyst::Xor::generate_transform(uint8_t key_data[], uint64_t length, uint64_t n) {
    std::vector<uint8_t> xor_transform;
    xor_transform.reserve(n);

    if (length >= n) {
        for (size_t i = 0; i < n; ++i) {
            xor_transform.emplace_back(key_data[i]);
        }
        return xor_transform;
    }

    for (size_t i = 0; i < length; ++i) {
        xor_transform.emplace_back(key_data[i]);
    }

    constexpr size_t digest_size = 32;
    uint8_t key_digest[digest_size];

    SHA3::SHA3_256(key_data, length, key_digest);
    for (size_t i = 0; i < digest_size; ++i) {
        xor_transform.emplace_back(key_digest[i]);
    }

    const size_t round_size = length > digest_size ? digest_size : length;
    
    while (xor_transform.size() < n) {
        uint8_t* const prev = std::max(xor_transform.data(), xor_transform.data() + xor_transform.size() - 2 * digest_size);
        uint8_t* const prev_hash = xor_transform.data() - digest_size;

        std::vector<uint8_t> round_data;
        round_data.resize(round_size);
        for (size_t i = 0; i < round_size; ++i) {
            round_data[i] = prev[i] & prev_hash[i];
        }

        uint8_t round_hash[digest_size];
        SHA3::SHA3_256(round_data.data(), round_size, round_hash);

        for (size_t i = 0; i < digest_size; ++i) {
            xor_transform.emplace_back(round_hash[i]);
        }
    }

    xor_transform.resize(n);
    return xor_transform;
}