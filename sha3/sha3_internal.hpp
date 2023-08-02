#pragma once

#include <iostream>
#include <cstring>
#include <cstdint>

// adapted from https://github.com/brainhub/SHA3IUF

namespace SHA3 {
    namespace internal {
        constexpr uint8_t SHA3_RETURN_OK = 0;
        constexpr uint8_t SHA3_RETURN_BAD_PARAMS = 1;

        namespace {
            static constexpr size_t SHA3_KECCAK_SPONGE_WORDS = (1600 / 8) / sizeof(uint64_t);
            static constexpr size_t KECCAK_ROUNDS = 24;

            static constexpr uint64_t SHA3_ROTL64(uint64_t x, uint64_t y) {
                return (x << y) | (x >> (8 * sizeof(uint64_t) - y));
            }

            static constexpr uint64_t keccakf_rndc[24] = {
                0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
                0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
                0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
                0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
                0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
                0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
            };
            static constexpr uint8_t keccakf_rotc[24] = {
                1,  3,  6,  10, 15, 21,
                28, 36, 45, 55, 2,  14,
                27, 41, 56, 8,  25, 43,
                62, 18, 39, 61, 20, 44
            };
            static constexpr uint8_t keccakf_piln[24] = {
                10, 7,  11, 17, 18, 3,
                5,  16, 8,  21, 24, 4,
                15, 23, 19, 13, 12, 2,
                20, 14, 22, 9,  6, 1
            };
        }

        union kstate {
            uint64_t s[SHA3_KECCAK_SPONGE_WORDS];
            uint8_t sb[SHA3_KECCAK_SPONGE_WORDS * 8];
        };

        struct sha3_context {
            constexpr sha3_context() {
                saved = 0;
                state = { 0 };
                byteIndex = 0;
                wordIndex = 0;
                capacityWords = 0;
            }

            uint64_t saved = 0;
            kstate state = { 0 };
            size_t byteIndex = 0;
            size_t wordIndex = 0;
            size_t capacityWords = 0;
        };

        template<uint16_t bitsize> constexpr uint8_t internal_init(sha3_context& ctx) {
            if constexpr (bitsize != 128 && bitsize != 224 && bitsize != 256 && bitsize != 384 && bitsize != 512) {
                return SHA3_RETURN_BAD_PARAMS;
            }

            ctx = sha3_context();
            ctx.capacityWords = 2 * bitsize / (8 * sizeof(uint64_t));

            return SHA3_RETURN_OK;
        }

        void internal_update(sha3_context&, const uint8_t*, size_t);
        uint8_t* internal_finalize(sha3_context&);
        uint8_t* internal_finalizeXOF(sha3_context&);

        template<uint16_t bitsize> uint8_t internal_sha3XOF(const uint8_t* buffer, size_t length, uint8_t* digest, size_t digest_size) {
            uint8_t err;
            sha3_context c;

            err = internal_init<bitsize>(c);

            if (err != SHA3_RETURN_OK) {
                return err;
            }

            internal_update(c, buffer, length);
            uint8_t* h = internal_finalizeXOF(c);

            if (digest_size > bitsize / 8) {
                digest_size = bitsize / 8;
            }
            memcpy(digest, h, digest_size);

            return SHA3_RETURN_OK;
        }
        template<uint16_t bitsize, size_t digest_size> uint8_t internal_sha3(const uint8_t* buffer, size_t length, uint8_t* digest) {
            uint8_t err;
            sha3_context c;

            err = internal_init<bitsize>(c);

            if (err != SHA3_RETURN_OK) {
                return err;
            }

            internal_update(c, buffer, length);
            uint8_t* h = internal_finalize(c);

            if constexpr (digest_size > bitsize / 8) {
                memcpy(digest, h, bitsize / 8);
            }
            else {
                memcpy(digest, h, digest_size);
            }

            return SHA3_RETURN_OK;
        }
    }
}