#include <iostream>
#include <vector>

#include <boost/multiprecision/cpp_int.hpp>

#include "../catalyst.hpp"

namespace {
    size_t get_bits(const bmp::cpp_int& n) {
        std::vector<uint8_t> _temp;
        export_bits(n, std::back_inserter(_temp), 1);
        return _temp.size();
    }
}

bmp::cpp_int catalyst::helper::bytes_to_int(const std::vector<uint8_t>& data) {
    bmp::cpp_int s = 0;
    for (uint64_t i = 0; i < data.size(); ++i) {
        s += (bmp::cpp_int)data[i] << (i * 8);
    }
    return s;
}

std::vector<uint64_t> catalyst::helper::generate_prime_numbers(const uint64_t& n) {
    std::vector<uint64_t> primes = { 2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137 };
    if (n <= primes.back()) {
        while (primes.back() > n) {
            primes.pop_back();
        }
        return primes;
    }

    uint64_t current = primes.back();
    while (current < n) {
        bool isPrime = true;
        
        for (uint64_t p = 2; p <= std::sqrt(current); ++p) {
            if (current % p == 0) {
                isPrime = true;
                break;
            }
        }

        if (isPrime) {
            primes.push_back(current);
        }
        ++current;
    }

    return primes;
}

uint64_t catalyst::helper::get_rounds(const bmp::cpp_int& key) {
    const size_t n_bits = get_bits(key);
    
    uint64_t s = 0;
    for (uint64_t i = 0; i < n_bits; ++i) {
        s += (uint64_t)((key >> i) & 1); 
    }

    uint64_t n_rounds = 0;
    for (const auto& p : generate_prime_numbers(s / 2)) {
        n_rounds += s % p;
    }

    return n_rounds;
}