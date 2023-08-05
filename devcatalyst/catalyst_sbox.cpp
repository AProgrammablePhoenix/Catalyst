#include <iostream>
#include <array>
#include <algorithm>
#include <cmath>
#include <cstdint>

#include "catalyst_internal.hpp"
#include "../sha3/sha3.hpp"

namespace {
    constexpr size_t sbox_size = catalyst::SBox::sbox_size;
    typedef std::array<std::array<uint8_t, sbox_size>, sbox_size> transform_matrix;

    // randomly generated (see: https://gist.github.com/AProgrammablePhoenix/e4b1d78dad93da0d36dab93c0683302a)
    // non-linearity: 98
    constexpr std::array<uint8_t, sbox_size> base_sbox = {
        0x4d, 0x02, 0xb1, 0xe6, 0xfe, 0x2e, 0x44, 0x89, 0x8b, 0xd4, 0x59, 0x27, 0x39, 0x78, 0x2a, 0x2f,
        0xf6, 0x1d, 0x81, 0x3c, 0xb5, 0x94, 0xa5, 0xfd, 0x73, 0xfc, 0x8c, 0x05, 0xf7, 0x6c, 0x45, 0x99,
        0xa7, 0x72, 0xe8, 0xae, 0xd3, 0x1c, 0xd9, 0x57, 0x13, 0xb2, 0xc5, 0x9c, 0x25, 0x65, 0x51, 0xa8,
        0xc1, 0xa1, 0x17, 0x2d, 0x7f, 0x18, 0x4e, 0x74, 0xd2, 0x63, 0x24, 0x21, 0x55, 0x71, 0x4b, 0xf1,
        0x93, 0xa9, 0xbe, 0xb7, 0x28, 0x6b, 0x09, 0x75, 0xcf, 0x76, 0xc9, 0xa6, 0xf3, 0x1b, 0xcd, 0xfb,
        0x14, 0x01, 0xec, 0x03, 0x6f, 0x6e, 0xea, 0x00, 0x40, 0x5c, 0x92, 0x7b, 0xef, 0x15, 0x52, 0x16,
        0xba, 0xcb, 0xca, 0xd6, 0xe9, 0xbd, 0x1e, 0x95, 0xb6, 0xe7, 0x19, 0x06, 0x35, 0x4f, 0x58, 0xdf,
        0x85, 0x86, 0x0c, 0x68, 0x4a, 0x12, 0x3f, 0xe2, 0x7c, 0xed, 0x37, 0x20, 0xc6, 0xc2, 0x36, 0x77,
        0x9f, 0x5e, 0x53, 0x31, 0x67, 0x9b, 0x49, 0xc0, 0x1a, 0xad, 0x84, 0xe1, 0x22, 0x79, 0xde, 0x0d,
        0x5b, 0x5a, 0x8d, 0x5d, 0x7a, 0xff, 0x0a, 0x61, 0x3e, 0x7d, 0x88, 0xd7, 0x1f, 0x33, 0xb8, 0x80,
        0xb3, 0x29, 0x83, 0xe0, 0xee, 0x46, 0xf5, 0xd8, 0x8f, 0xeb, 0x07, 0x62, 0x50, 0xf8, 0x43, 0x8e,
        0x9d, 0xf0, 0x38, 0xc7, 0xc3, 0x0f, 0x08, 0xb4, 0x54, 0xa4, 0x98, 0x34, 0xac, 0xbf, 0xc8, 0x2c,
        0x64, 0x96, 0x23, 0x48, 0x10, 0x66, 0xdb, 0xa2, 0xdd, 0xfa, 0x8a, 0x56, 0xbc, 0x3b, 0x91, 0x60,
        0xcc, 0xb0, 0x70, 0x04, 0xaa, 0xd0, 0x0b, 0xa3, 0x6d, 0x97, 0xda, 0x47, 0xe4, 0x90, 0xe3, 0xab,
        0xa0, 0x6a, 0xf2, 0x69, 0xbb, 0x3d, 0x9a, 0x41, 0x0e, 0x32, 0x7e, 0xe5, 0x30, 0xb9, 0x82, 0x4c,
        0xd1, 0xaf, 0xd5, 0xc4, 0xf9, 0x11, 0x87, 0xdc, 0x3a, 0xce, 0x26, 0x2b, 0x5f, 0xf4, 0x42, 0x9e
    };
    // inverse of the base sbox
    constexpr std::array<uint8_t, sbox_size> inverse_base_sbox = {
        0x57, 0x51, 0x01, 0x53, 0xd3, 0x1b, 0x6b, 0xaa, 0xb6, 0x46, 0x96, 0xd6, 0x72, 0x8f, 0xe8, 0xb5,
        0xc4, 0xf5, 0x75, 0x28, 0x50, 0x5d, 0x5f, 0x32, 0x35, 0x6a, 0x88, 0x4d, 0x25, 0x11, 0x66, 0x9c,
        0x7b, 0x3b, 0x8c, 0xc2, 0x3a, 0x2c, 0xfa, 0x0b, 0x44, 0xa1, 0x0e, 0xfb, 0xbf, 0x33, 0x05, 0x0f,
        0xec, 0x83, 0xe9, 0x9d, 0xbb, 0x6c, 0x7e, 0x7a, 0xb2, 0x0c, 0xf8, 0xcd, 0x13, 0xe5, 0x98, 0x76,
        0x58, 0xe7, 0xfe, 0xae, 0x06, 0x1e, 0xa5, 0xdb, 0xc3, 0x86, 0x74, 0x3e, 0xef, 0x00, 0x36, 0x6d,
        0xac, 0x2e, 0x5e, 0x82, 0xb8, 0x3c, 0xcb, 0x27, 0x6e, 0x0a, 0x91, 0x90, 0x59, 0x93, 0x81, 0xfc,
        0xcf, 0x97, 0xab, 0x39, 0xc0, 0x2d, 0xc5, 0x84, 0x73, 0xe3, 0xe1, 0x45, 0x1d, 0xd8, 0x55, 0x54,
        0xd2, 0x3d, 0x21, 0x18, 0x37, 0x47, 0x49, 0x7f, 0x0d, 0x8d, 0x94, 0x5b, 0x78, 0x99, 0xea, 0x34,
        0x9f, 0x12, 0xee, 0xa2, 0x8a, 0x70, 0x71, 0xf6, 0x9a, 0x07, 0xca, 0x08, 0x1a, 0x92, 0xaf, 0xa8,
        0xdd, 0xce, 0x5a, 0x40, 0x15, 0x67, 0xc1, 0xd9, 0xba, 0x1f, 0xe6, 0x85, 0x2b, 0xb0, 0xff, 0x80,
        0xe0, 0x31, 0xc7, 0xd7, 0xb9, 0x16, 0x4b, 0x20, 0x2f, 0x41, 0xd4, 0xdf, 0xbc, 0x89, 0x23, 0xf1,
        0xd1, 0x02, 0x29, 0xa0, 0xb7, 0x14, 0x68, 0x43, 0x9e, 0xed, 0x60, 0xe4, 0xcc, 0x65, 0x42, 0xbd,
        0x87, 0x30, 0x7d, 0xb4, 0xf3, 0x2a, 0x7c, 0xb3, 0xbe, 0x4a, 0x62, 0x61, 0xd0, 0x4e, 0xf9, 0x48,
        0xd5, 0xf0, 0x38, 0x24, 0x09, 0xf2, 0x63, 0x9b, 0xa7, 0x26, 0xda, 0xc6, 0xf7, 0xc8, 0x8e, 0x6f,
        0xa3, 0x8b, 0x77, 0xde, 0xdc, 0xeb, 0x03, 0x69, 0x22, 0x64, 0x56, 0xa9, 0x52, 0x79, 0xa4, 0x5c,
        0xb1, 0x3f, 0xe2, 0x4c, 0xfd, 0xa6, 0x10, 0x1c, 0xad, 0xf4, 0xc9, 0x4f, 0x19, 0x17, 0x04, 0x95
    };

    constexpr transform_matrix matmul(uint8_t key_data[], size_t length) {
        transform_matrix result = { 0 };
        
        std::vector<uint8_t> normalized_key;
        normalized_key.reserve(sbox_size);
        
        if (length == sbox_size) {
            normalized_key.insert(normalized_key.end(), key_data, key_data + length);
        }
        else if (length < sbox_size) {
            normalized_key.insert(normalized_key.end(), key_data, key_data + length);
            while (normalized_key.size() < sbox_size) {
                const uint8_t padding = key_data[key_data[length - 1] % length];
                normalized_key.emplace_back(padding);
            }
        }
        else {
            for (size_t i = 0; i < length; i += length / 4) {
                constexpr size_t block_size = sbox_size / 4;

                std::vector<uint8_t> digest;
                digest.resize(block_size);
                SHA3::SHAKE256(key_data + i, length / 4, digest.data(), block_size);

                normalized_key.insert(normalized_key.end(), digest.cbegin(), digest.cend());
            }
        }

        for (size_t i = 0; i < sbox_size; ++i) {
            for (size_t j = 0; j < sbox_size; ++j) {
                result[i][j] = base_sbox[i] * normalized_key[j];
            }
        }

        return result;
    }

    constexpr std::array<uint8_t, 3> getShiftVector(const transform_matrix& tm, uint8_t shift) {
        std::array<uint8_t, 3> v = { 0 };

        v[0] = tm[0][shift];
        v[1] = tm[shift][0];
        v[2] = tm[v[0]][v[1]];

        return v;
    }

    constexpr uint8_t getShift(const std::array<uint8_t, 3>& shift_vector) {
        return (uint8_t)sqrt(
            shift_vector[0] * shift_vector[0] +
            shift_vector[1] * shift_vector[1] +
            shift_vector[2] * shift_vector[2]
        );
    }
}

const std::array<uint8_t, sbox_size>& catalyst::SBox::get_sbox() {
    return base_sbox;
}
const std::array<uint8_t, sbox_size>& catalyst::SBox::get_inverse_sbox() {
    return inverse_base_sbox;
}
std::array<uint8_t, sbox_size> catalyst::SBox::get_transform(uint8_t key_data[], uint64_t length) {
    std::array<uint8_t, sbox_size> transform_v = { 0 };
    
    const transform_matrix transform_matrix = matmul(key_data, length);
    const std::array<uint8_t, 3> genesis_v = getShiftVector(transform_matrix, 0);
    transform_v[0] = getShift(genesis_v);

    for (size_t i = 1; i < sbox_size; ++i) {
        const std::array<uint8_t, 3> shift_v = getShiftVector(transform_matrix, transform_v[i - 1] + i);
        transform_v[i] = getShift(shift_v);
    }

    return transform_v;
}