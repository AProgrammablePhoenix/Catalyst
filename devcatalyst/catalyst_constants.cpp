#include <iostream>
#include <bit>
#include <algorithm>
#include <cmath>
#include <vector>
#include <array>

#include "catalyst_internal.hpp"
#include "../sha3/sha3.hpp"

namespace {
    static constexpr std::vector<uint32_t> gen_constants_1() {
        std::vector<uint32_t> constants;

        // 2 would yield 0
        constexpr uint32_t primes[32] = {
            3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137
        };
        double temp;

        for (const auto& p : primes) {
            constants.push_back(
                uint32_t(modf((p + log2(p)) * log2(p), &temp) * (1LL << 32LL))
            );
        }

        return constants;
    }
    static constexpr std::vector<uint32_t> gen_constants_2() {
        std::vector<uint32_t> constants;

        // 2 would yield 0
        constexpr uint32_t primes[32] = {
            3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137
        };
        double temp;

        for (const auto& p : primes) {
            constants.push_back(
                uint32_t(modf(pow(log2(p), pow(p, 1./3.)), &temp) * (1LL << 32LL))
            );
        }

        return constants;
    }
    static constexpr std::vector<uint32_t> gen_constants_3() {
        std::vector<uint32_t> constants;

        // 2 would yield 0
        constexpr uint32_t primes[32] = {
            3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137
        };
        double temp;

        for (const auto& p : primes) {
            constants.push_back(
                uint32_t(modf(pow(p, log2(pow(p, 1./3.))), &temp) * (1LL << 32LL))
            );
        }

        return constants;
    }
    static constexpr std::vector<uint32_t> gen_constants_4() {
        std::vector<uint32_t> constants;

        constexpr uint32_t primes[32] = {
            2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131
        };
        double temp;

        for (const auto& p : primes) {
            constants.push_back(
                uint32_t(modf(log2(p) * fabs(cos(p)), &temp) * (1LL << 32LL))
            );
        }

        return constants;
    }
    static constexpr std::array<std::vector<uint32_t>, 4> gen_sigmas() {
        std::array<std::vector<uint32_t>, 4> constants;

        for (size_t i = 0; i < 32; ++i) {
            constants[0].push_back((constants[0][i] ^ constants[3][i]) | (constants[1][i] >> 16 & constants[2][i]));
            constants[1].push_back((constants[1][i] ^ constants[0][i]) | (constants[2][i] >> 16 & constants[3][i]));
            constants[2].push_back((constants[2][i] ^ constants[1][i]) | (constants[3][i] >> 16 & constants[0][i]));
            constants[3].push_back((constants[3][i] ^ constants[2][i]) | (constants[0][i] >> 16 & constants[1][i]));
        }

        return constants;
    }
}

// addition transform constants
std::vector<uint32_t> catalyst::constants::get_constants_1() {
    std::vector<uint32_t> _local_set = {
        0x4459b1d0, 0x40eab5, 0x8860bd10, 0x57b72e3,
        0xcc8953b5, 0x31b873f9, 0xc16929cf, 0x812962f9,
        0x7b3ee107, 0x1fc81410, 0xe35fb133, 0x5ced48c9,
        0xc6136868, 0xeb4c5294, 0x638c1ef5, 0xae72242e,
        0xf2d8f446, 0x39b4b878, 0x7391407f, 0x2bce93c3,
        0xbc802d55, 0xc4f76f44, 0x46808992, 0xc019e6a2,
        0xcfa6dd6c, 0x6b39558b, 0xc8cad002, 0x8a5856ed,
        0x31efb40c, 0x6798610f, 0xd8f2a29f, 0xcffd09f1
    };
    
    if constexpr (std::endian::native == std::endian::little) {
        for (auto& e : _local_set) {
            e = std::byteswap(e);
        }
    }

    return _local_set;
}

std::vector<uint32_t> catalyst::constants::get_constants_2() {
    std::vector<uint32_t> _local_set = {
        0xf169c4c2, 0x39045f64, 0x342c8a75, 0xcd8891ce,
        0xaf49aab6, 0x580b5eb9, 0x72fe1c34, 0x2172b3c7,
        0x88138f6d, 0x7782dba8, 0xa163efc6, 0x50267b8e,
        0x534e0177, 0xc3d11f6b, 0x7b8013f4, 0xb3ac1d61,
        0xf19b9247, 0xf0a613fd, 0x336f0ed3, 0x9972f2cd,
        0x7ed6e070, 0x107052b2, 0xd975f04a, 0x2de33c0e,
        0x6ca73773, 0xc0b639ac, 0x97ef8697, 0x4885f609,
        0x5b4841b7, 0xf8e9c171, 0x271280c7, 0x435b6209
    }; 

    if constexpr (std::endian::native == std::endian::little) {
        for (auto& e : _local_set) {
            e = std::byteswap(e);
        }
    }

    return _local_set;
}

std::vector<uint32_t> catalyst::constants::get_constants_3() {
    std::vector<uint32_t> _local_set = {
        0xc96af52f, 0x79a9f8f9, 0x2d80c2da, 0xe183d1f2,
        0xa9209bf6, 0x79c7bf1a, 0xaacf0767, 0xde0ca67,
        0x665c2389, 0x4a601e36, 0xa32f21ca, 0xe9576a34,
        0xa00e390a, 0x351d6ad0, 0x9e806ff7, 0xc4dc8415,
        0x14c73dca, 0xacb34c09, 0x402e00cb, 0x208c3cec,
        0x3ad75781, 0x3a9512cd, 0x3daa81cf, 0xadb53147,
        0x179728be, 0x50b23f63, 0x58748336, 0x9175ca3f,
        0x206eda7e, 0xfd017430, 0x44742793, 0xcd1a0ae1
    };
    
    if constexpr (std::endian::native == std::endian::little) {
        for (auto& e : _local_set) {
            e = std::byteswap(e);
        }
    }

    return _local_set;
}

std::vector<uint32_t> catalyst::constants::get_constants_4() {
    std::vector<uint32_t> _local_set = {
        0x6a88995d, 0x91b09a1e, 0xa89cd732, 0x1dd10e8e,
        0x3eb61e1, 0x5ba2bfe7, 0x1feda507, 0x332fa1af,
        0x6909a112, 0xa2510d6e, 0x8824e929, 0xfcc58353,
        0x4a2b309d, 0x31eff81, 0x83137335, 0x4285943b,
        0x89369f35, 0x87de1e55, 0x240df1f3, 0xe6816072,
        0x8e913ecb, 0xa5e39de0, 0x97408283, 0x4dc3e80f,
        0x1b1bcf8a, 0xf06c98f7, 0x3afaa8c8, 0xa018a608,
        0xe7beedf3, 0xc9b39703, 0x9fb6e4fc, 0x1be69eb8
    };
    
    if constexpr (std::endian::native == std::endian::little) {
        for (auto& e : _local_set) {
            e = std::byteswap(e);
        }
    }

    return _local_set;
}

const std::vector<uint32_t>& catalyst::constants::get_constants_set(uint8_t key_data[], uint64_t length) {
    uint64_t S = 0;

    for (uint64_t i = 0; i < length; ++i) {
        S += key_data[i] % 4;
    }

    return constants[S % 4];
}

std::vector<uint32_t> catalyst::constants::extend_constants(const std::vector<uint32_t>& constants, uint64_t length) {    
    std::vector<uint32_t> ret = constants;

    while (ret.size() * sizeof(uint32_t) < length) {
        std::vector<uint8_t> hash(32);
        SHA3::SHAKE256((uint8_t*)ret.data(), ret.size()*sizeof(uint32_t), hash.data(), 32);

        std::vector<uint32_t> hash32;
        for (size_t i = 0; i < 8; ++i) {
            hash32.push_back(*(uint32_t*)&hash[i * 4]);
        }

        ret.insert(ret.end(), hash32.begin(), hash32.end());
    }
    return ret;
}

// sigma transform constants
std::array<uint32_t, 32> catalyst::constants::sigma::get_constants_1() {
    std::array<uint32_t, 32> _local_set = {
        0x8d28d3ee, 0xab70f0d9,0x226afc28, 0x6d7caa99,
        0x543262ef, 0x1ecc9b7a,0xc88c84de, 0x56c3c6b3,
        0x15407f16, 0x7e19b9ff,0x1a587feb, 0x9acb2ee9,
        0xf5583e8c, 0x15ad5bfd,0xc06d9ff2, 0x15b0f7ec,
        0x736bef7b, 0x2da6fbbe,0x8cb19e57, 0xb1f3cfed,
        0x9e135132, 0xa4f29473,0x110bcaf1, 0xad0edead,
        0xe612bfd7, 0x7ccdf59b,0xca7834f2, 0xe5f041ba,
        0xff5977d6, 0xcf62bef, 0x63464447, 0x49971bd4
    };

    if constexpr (std::endian::native == std::endian::little) {
        for (auto& e : _local_set) {
            e = std::byteswap(e);
        }
    }

    return _local_set;
}

std::array<uint32_t, 32> catalyst::constants::sigma::get_constants_2() {
    std::array<uint32_t, 32> _local_set = {
        0x127538f5, 0xd1b5f4b9, 0x6537dcbc, 0x2de3f3d9,
        0x3f9e263,  0x402db37b, 0xfb35f7b7, 0x3ed17fa2,
        0x6a6e2df3, 0xb8cf5a6a, 0xf55e3c42, 0x4733cf6c,
        0x1f695f9d, 0xff4d9d2a, 0x10d1f1b,  0x4f39df1d,
        0x166430b,  0x85ab1acd, 0xac4eff40, 0xe61bcb6,
        0x25cdd7c6, 0xf63dc7d4, 0xd879f59f, 0xacdafbed,
        0x1fea1bab, 0x276cefbb, 0x9556375f, 0xe4a0ddc2,
        0xbbf5bfea, 0x7ea071df, 0x5822f2ff, 0xf86be68e
    };

    if constexpr (std::endian::native == std::endian::little) {
        for (auto& e : _local_set) {
            e = std::byteswap(e);
        }
    }

    return _local_set;
}

std::array<uint32_t, 32> catalyst::constants::sigma::get_constants_3() {
    std::array<uint32_t, 32> _local_set = {
        0xed315b38, 0x9da7ad40, 0xaf48ac99, 0x3c400b2c,
        0x4031e946, 0xa3e1ec31, 0x531b31d9, 0xa079bbad,
        0xe4ac5fef, 0x9ec5ea3d, 0xcce4de3,  0xba1171b9,
        0x7d3851f3, 0xbb75ccff, 0x37c04e7,  0x749972f7,
        0x8daf5cf7, 0xf45f155c, 0x180ed173, 0x21cefeb9,
        0xf1b7817c, 0x7f40e5ae, 0x8571dfe6, 0x490d5fc0,
        0xcd1fb2ff, 0xcf063598, 0xa105dbcf, 0x363cf8db,
        0xc99be77b, 0x41b5e807, 0x54a7f6e3, 0xe868f98e
    };

    if constexpr (std::endian::native == std::endian::little) {
        for (auto& e : _local_set) {
            e = std::byteswap(e);
        }
    }

    return _local_set;
}

std::array<uint32_t, 32> catalyst::constants::sigma::get_constants_4() {
    std::array<uint32_t, 32> _local_set = {
        0x726ce2b3, 0xe7621de8, 0xe8151cb5, 0x7cdfd2fc,
        0x17facbab, 0xfd006d72, 0x60a2eeb5, 0xc86bff3e,
        0x9b82578f, 0x581331fc, 0xe3c82bab, 0x67e99255,
        0x97096dea, 0x51959376, 0xc21c931f, 0x2e107da6,
        0xffa2f3fd, 0x5c526dbb, 0x38f16f64, 0x9e5c4fd7,
        0x4a6956bc, 0x2d8f769f, 0x4c03faab, 0x48d9f6e4,
        0x34e7ac4c, 0x94a7dee0, 0xfe2b8ef2, 0x376ced71,
        0x8d37d8d7, 0x33e3bb74, 0x6fc3d2fb, 0x5994fdd7
    };

    if constexpr (std::endian::native == std::endian::little) {
        for (auto& e : _local_set) {
            e = std::byteswap(e);
        }
    }

    return _local_set;
}
const std::array<uint32_t, 32>& catalyst::constants::sigma::get_constants_set(uint8_t key_data[], uint64_t length) {
    uint64_t S = 0;

    for (uint64_t i = 0; i < length; ++i) {
        S += key_data[i] % 4;
    }

    return constants[S % 4];
}