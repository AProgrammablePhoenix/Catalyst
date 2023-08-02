#include <iostream>
#include <vector>

#include "../catalyst.hpp"
#include "../sha3/sha3.hpp"

uint32_t catalyst::sigmas::sigma0(uint32_t x) {
    return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3);
}
uint32_t catalyst::sigmas::sigma1(uint32_t x) {
    return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10);
}
uint32_t catalyst::sigmas::Sigma0(uint32_t x) {
    return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10);
}
uint32_t catalyst::sigmas::Sigma1(uint32_t x) {
    return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7);
}

uint32_t catalyst::sigmas::Isigma0(uint32_t x) {
    constexpr uint32_t singleton_inverses[32] = {
        0x185744e9, 0x30ae89d2, 0x615d13a4, 0xdaed63a1, 0x9cd03a8e, 0x08fdcc39,
        0x11fb9872, 0x23f730e4, 0x5fb92521, 0xbf724a42, 0x57ee6948, 0xafdcd290,
        0x76b358ec, 0xf531f531, 0xc36917ae, 0xb78f9679, 0x4615d13e, 0x947ce695,
        0x19a4740f, 0x2b1facf7, 0x4e681d07, 0x84877ee7, 0x385344eb, 0x70a689d6,
        0xf91a5745, 0xc36917af, 0xb78f967b, 0x4615d13a, 0x8c2ba274, 0x290afdcd,
        0x4a42bf73, 0x94857ee6
    };

    const uint32_t xn = ~x;
    uint32_t r = ((xn & 1) - 1) & singleton_inverses[0];
    for (uint32_t i = 1; i < 32; ++i) {
        r ^= (((xn >> i) & 1) - 1) & singleton_inverses[i];
    }

    return r;
}
uint32_t catalyst::sigmas::Isigma1(uint32_t x) {
    constexpr uint32_t singleton_inverses[32] = {
        0x2ccfffed, 0x75500037, 0xeaa0006e, 0x589d5570, 0xb13aaae0, 0xc367ff81,
        0x27dd5543, 0x4fbaaa86, 0xb3baaae1, 0xc667ff83, 0x2ddd5547, 0x5bbaaa8e,
        0x9bbaaaf1, 0x9667ffa3, 0x8ddd5507, 0x9667ffa2, 0x8ddd5505, 0x9667ffa6, 
        0x8ddd550d, 0x9667ffb6, 0x8ddd552d, 0x9667fff6, 0x8ddd55ad, 0x9667fef6,
        0x8ddd57ad, 0xbaa8051b, 0xf88d5f9a, 0x50081575, 0xa0102aea, 0xe132ff95,
        0x6377556b, 0xc6eeaad6
    };

    const uint32_t xn = ~x;
    uint32_t r = ((xn & 1) - 1) & singleton_inverses[0];
    for (uint32_t i = 1; i < 32; ++i) {
        r ^= (((xn >> i) & 1) - 1) & singleton_inverses[i];
    }

    return r;
}
uint32_t catalyst::sigmas::ISigma0(uint32_t x) {
    constexpr uint32_t singleton_inverses[32] = {
        0xcbd1a68d, 0x97a34d1b, 0x2f469a37, 0x5e8d346e, 0xbd1a68dc, 0x7a34d1b9,
        0xf469a372, 0xe8d346e5, 0xd1a68dcb, 0xa34d1b97, 0x469a372f, 0x8d346e5e,
        0x1a68dcbd, 0x34d1b97a, 0x69a372f4, 0xd346e5e8, 0xa68dcbd1, 0x4d1b97a3,
        0x9a372f46, 0x346e5e8d, 0x68dcbd1a, 0xd1b97a34, 0xa372f469, 0x46e5e8d3,
        0x8dcbd1a6, 0x1b97a34d, 0x372f469a, 0x6e5e8d34, 0xdcbd1a68, 0xb97a34d1,
        0x72f469a3, 0xe5e8d346
    };

    const uint32_t xn = ~x;
    uint32_t r = ((xn & 1) - 1) & singleton_inverses[0];
    for (uint32_t i = 1; i < 32; ++i) {
        r ^= (((xn >> i) & 1) - 1) & singleton_inverses[i];
    }

    return r;
}
uint32_t catalyst::sigmas::ISigma1(uint32_t x) {
    constexpr uint32_t singleton_inverses[32] = {
        0x6ab84f6c, 0xd5709ed8, 0xaae13db1, 0x55c27b63, 0xab84f6c6, 0x5709ed8d,
        0xae13db1a, 0x5c27b635, 0xb84f6c6a, 0x709ed8d5, 0xe13db1aa, 0xc27b6355,
        0x84f6c6ab, 0x09ed8d57, 0x13db1aae, 0x27b6355c, 0x4f6c6ab8, 0x9ed8d570,
        0x3db1aae1, 0x7b6355c2, 0xf6c6ab84, 0xed8d5709, 0xdb1aae13, 0xb6355c27,
        0x6c6ab84f, 0xd8d5709e, 0xb1aae13d, 0x6355c27b, 0xc6ab84f6, 0x8d5709ed,
        0x1aae13db, 0x355c27b6
    };
    
    const uint32_t xn = ~x;
    uint32_t r = ((xn & 1) - 1) & singleton_inverses[0];
    for (uint32_t i = 1; i < 32; ++i) {
        r ^= (((xn >> i) & 1) - 1) & singleton_inverses[i];
    }

    return r;
}

uint32_t (*catalyst::sigmas::get_sigma(uint8_t key_data[], uint64_t length)) (uint32_t) {
    uint64_t key_bit_count = 0;
    for (size_t  i = 0; i < length; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            key_bit_count += (key_data[i] >> j) & 1;
        }
    }

    uint8_t key_shake128[16];
    SHA3::SHAKE128(key_data, length, key_shake128, 16);

    uint64_t hash_bit_count = 0;
    for (size_t  i = 0; i < 16; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            hash_bit_count += (key_shake128[i] >> j) & 1;
        }
    }

    return catalyst::sigmas::sigmas[(key_bit_count % hash_bit_count) % 4];
}

uint32_t (*catalyst::sigmas::get_Isigma(uint8_t key_data[], uint64_t length)) (uint32_t) {
    uint64_t key_bit_count = 0;
    for (size_t  i = 0; i < length; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            key_bit_count += (key_data[i] >> j) & 1;
        }
    }

    uint8_t key_shake128[16];
    SHA3::SHAKE128(key_data, length, key_shake128, 16);

    uint64_t hash_bit_count = 0;
    for (size_t  i = 0; i < 16; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            hash_bit_count += (key_shake128[i] >> j) & 1;
        }
    }

    return catalyst::sigmas::Isigmas[(key_bit_count % hash_bit_count) % 4];
}