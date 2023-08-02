#pragma once

#include <iostream>
#include <cstdint>
#include <vector>

namespace SHA3 {
    uint8_t SHA3_224(const uint8_t* data, size_t len, uint8_t* digest);
    uint8_t SHA3_224(const std::vector<uint8_t>& data, std::vector<uint8_t>& digest);

    uint8_t SHA3_256(const uint8_t* data, size_t len, uint8_t* digest);
    uint8_t SHA3_256(const std::vector<uint8_t>& data, std::vector<uint8_t>& digest);

    uint8_t SHA3_384(const uint8_t* data, size_t len, uint8_t* digest);
    uint8_t SHA3_384(const std::vector<uint8_t>& data, std::vector<uint8_t>& digest);

    uint8_t SHA3_512(const uint8_t* data, size_t len, uint8_t* digest);
    uint8_t SHA3_512(const std::vector<uint8_t>& data, std::vector<uint8_t>& digest);

    uint8_t SHAKE128(const uint8_t* data, size_t len, uint8_t* digest, size_t digest_len);
    uint8_t SHAKE128(const std::vector<uint8_t>& data, std::vector<uint8_t>& digest, size_t digest_len);

    uint8_t SHAKE256(const uint8_t* data, size_t len, uint8_t* digest, size_t digest_len);
    uint8_t SHAKE256(const std::vector<uint8_t>& data, std::vector<uint8_t>& digest, size_t digest_len);
}