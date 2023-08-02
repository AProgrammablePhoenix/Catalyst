#include <iostream>
#include <bit>

#include "sha3_internal.hpp"

using namespace SHA3::internal;

// adapted from https://github.com/brainhub/SHA3IUF

namespace {
    static constexpr void keccakf(uint64_t s[25]) {
        uint64_t t = 0, bc[5] = { 0 };

        for (size_t round = 0; round < KECCAK_ROUNDS; round++) {
            for (size_t i = 0; i < 5; ++i) {
                bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
            }

            for (size_t i = 0; i < 5; ++i) {
                t = bc[(i + 4) % 5] ^ SHA3_ROTL64(bc[(i + 1) % 5], 1);
                for(size_t j = 0; j < 25; j += 5) {
                    s[j + i] ^= t;
                }
            }

            t = s[1];
            for (size_t i = 0; i < 24; ++i) {
                size_t j = keccakf_piln[i];
                bc[0] = s[j];
                s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
                t = bc[0];
            }

            for (size_t j = 0; j < 25; j += 5) {
                for(size_t i = 0; i < 5; ++i) {
                    bc[i] = s[j + i];
                }
                for(size_t i = 0; i < 5; ++i) {
                    s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }

            s[0] ^= keccakf_rndc[round];
        }
    }
}

void SHA3::internal::internal_update(sha3_context& ctx, const uint8_t* buf, size_t len) {
    size_t old_tail = (8 - ctx.byteIndex) & 7;

    size_t words;
    size_t tail;

    if (len < old_tail) {
        while (len--) {
            ctx.saved |= (uint64_t) (*(buf++)) << ((ctx.byteIndex++) * 8);
        }
        return;
    }

    if(old_tail) {
        len -= old_tail;
        while (old_tail--) {
            ctx.saved |= (uint64_t) (*(buf++)) << ((ctx.byteIndex++) * 8);
        }

        ctx.state.s[ctx.wordIndex] ^= ctx.saved;
        ctx.byteIndex = 0;
        ctx.saved = 0;
        if (++ctx.wordIndex == SHA3_KECCAK_SPONGE_WORDS - ctx.capacityWords) {
            keccakf(ctx.state.s);
            ctx.wordIndex = 0;
        }
    }

    words = len / sizeof(uint64_t);
    tail = len - words * sizeof(uint64_t);

    for(size_t i = 0; i < words; ++i, buf += sizeof(uint64_t)) {
        const uint64_t t = (uint64_t) (buf[0]) |
                ((uint64_t) (buf[1]) << 8 * 1) |
                ((uint64_t) (buf[2]) << 8 * 2) |
                ((uint64_t) (buf[3]) << 8 * 3) |
                ((uint64_t) (buf[4]) << 8 * 4) |
                ((uint64_t) (buf[5]) << 8 * 5) |
                ((uint64_t) (buf[6]) << 8 * 6) |
                ((uint64_t) (buf[7]) << 8 * 7);

        ctx.state.s[ctx.wordIndex] ^= t;
        if(++ctx.wordIndex ==
                (SHA3_KECCAK_SPONGE_WORDS - ctx.capacityWords)) {
            keccakf(ctx.state.s);
            ctx.wordIndex = 0;
        }
    }

    while (tail--) {
        ctx.saved |= (uint64_t) (*(buf++)) << ((ctx.byteIndex++) * 8);
    }
}

uint8_t* SHA3::internal::internal_finalize(sha3_context& ctx) {
    uint64_t t = (uint64_t)(((uint64_t)(0x02 | (1 << 2))) << ((ctx.byteIndex) * 8));

    ctx.state.s[ctx.wordIndex] ^= ctx.saved ^ t;
    ctx.state.s[SHA3_KECCAK_SPONGE_WORDS - ctx.capacityWords - 1] ^= (uint64_t)0x8000000000000000;
    keccakf(ctx.state.s);
    
    if constexpr (std::endian::native != std::endian::little) {
        for(uint64_t i = 0; i < SHA3_KECCAK_SPONGE_WORDS; ++i) {
            const uint32_t t1    = (uint32_t)ctx.state.s[i];
            const uint32_t t2    = (uint32_t)((ctx.state.s[i] >> 16) >> 16);
            ctx.state.sb[i * 8 + 0] = (uint8_t)t1;
            ctx.state.sb[i * 8 + 1] = (uint8_t)(t1 >> 8);
            ctx.state.sb[i * 8 + 2] = (uint8_t)(t1 >> 16);
            ctx.state.sb[i * 8 + 3] = (uint8_t)(t1 >> 24);
            ctx.state.sb[i * 8 + 4] = (uint8_t)t2;
            ctx.state.sb[i * 8 + 5] = (uint8_t)(t2 >> 8);
            ctx.state.sb[i * 8 + 6] = (uint8_t)(t2 >> 16);
            ctx.state.sb[i * 8 + 7] = (uint8_t)(t2 >> 24);
        }
    }

    return ctx.state.sb;
}

uint8_t* SHA3::internal::internal_finalizeXOF(sha3_context& ctx) {
    uint64_t t = (uint64_t)(((uint64_t)(0x0f | (1 << 4))) << ((ctx.byteIndex) * 8));

    ctx.state.s[ctx.wordIndex] ^= ctx.saved ^ t;
    ctx.state.s[SHA3_KECCAK_SPONGE_WORDS - ctx.capacityWords - 1] ^= (uint64_t)0x8000000000000000;
    keccakf(ctx.state.s);
    
    if constexpr (std::endian::native != std::endian::little) {
        for(uint64_t i = 0; i < SHA3_KECCAK_SPONGE_WORDS; ++i) {
            const uint32_t t1    = (uint32_t)ctx.state.s[i];
            const uint32_t t2    = (uint32_t)((ctx.state.s[i] >> 16) >> 16);
            ctx.state.sb[i * 8 + 0] = (uint8_t)t1;
            ctx.state.sb[i * 8 + 1] = (uint8_t)(t1 >> 8);
            ctx.state.sb[i * 8 + 2] = (uint8_t)(t1 >> 16);
            ctx.state.sb[i * 8 + 3] = (uint8_t)(t1 >> 24);
            ctx.state.sb[i * 8 + 4] = (uint8_t)t2;
            ctx.state.sb[i * 8 + 5] = (uint8_t)(t2 >> 8);
            ctx.state.sb[i * 8 + 6] = (uint8_t)(t2 >> 16);
            ctx.state.sb[i * 8 + 7] = (uint8_t)(t2 >> 24);
        }
    }

    return ctx.state.sb;
}