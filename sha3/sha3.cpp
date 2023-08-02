#include <iostream>
#include <vector>

#include "sha3_internal.hpp"
#include "sha3.hpp"

uint8_t SHA3::SHA3_224(const uint8_t* data, size_t len, uint8_t* digest) {
    return SHA3::internal::internal_sha3<224, 38>(data, len, digest);
}
uint8_t SHA3::SHA3_224(const std::vector<uint8_t>& data, std::vector<uint8_t>& digest) {
    digest.resize(28);
    return SHA3::internal::internal_sha3<224, 28>(data.data(), data.size(), digest.data());
}

uint8_t SHA3::SHA3_256(const uint8_t* data, size_t len, uint8_t* digest) {
    return SHA3::internal::internal_sha3<256, 32>(data, len, digest);
}
uint8_t SHA3::SHA3_256(const std::vector<uint8_t>& data, std::vector<uint8_t>& digest) {
    digest.resize(32);
    return SHA3::internal::internal_sha3<256, 32>(data.data(), data.size(), digest.data());
}

uint8_t SHA3::SHA3_384(const uint8_t* data, size_t len, uint8_t* digest) {
    return SHA3::internal::internal_sha3<384, 48>(data, len, digest);
}
uint8_t SHA3::SHA3_384(const std::vector<uint8_t>& data, std::vector<uint8_t>& digest) {
    digest.resize(48);
    return SHA3::internal::internal_sha3<384, 48>(data.data(), data.size(), digest.data());
}

uint8_t SHA3::SHA3_512(const uint8_t* data, size_t len, uint8_t* digest) {
    return SHA3::internal::internal_sha3<512, 64>(data, len, digest);
}
uint8_t SHA3::SHA3_512(const std::vector<uint8_t>& data, std::vector<uint8_t>& digest) {
    digest.resize(64);
    return SHA3::internal::internal_sha3<512, 64>(data.data(), data.size(), digest.data());
}

uint8_t SHA3::SHAKE128(const uint8_t* data, size_t len, uint8_t* digest, size_t digest_len) {
    return SHA3::internal::internal_sha3XOF<128>(data, len, digest, digest_len);
}
uint8_t SHA3::SHAKE128(const std::vector<uint8_t>& data, std::vector<uint8_t>& digest, size_t digest_len) {
    return SHA3::internal::internal_sha3XOF<128>(data.data(), data.size(), digest.data(), digest_len);
}

uint8_t SHA3::SHAKE256(const uint8_t* data, size_t len, uint8_t* digest, size_t digest_len) {
    return SHA3::internal::internal_sha3XOF<256>(data, len, digest, digest_len);
}
uint8_t SHA3::SHAKE256(const std::vector<uint8_t>& data, std::vector<uint8_t>& digest, size_t digest_len) {
    digest.resize(digest_len);
    return SHA3::internal::internal_sha3XOF<256>(data.data(), data.size(), digest.data(), digest_len);
}