#include "sha256_ethereum.hpp"

std::vector<unsigned long> bit_list_to_ints(std::vector<bool> bit_list, const size_t wordsize) {
    std::vector<unsigned long> res;
    size_t iterations = bit_list.size()/wordsize+1;
    for (size_t i = 0; i < iterations; ++i) {
        unsigned long current = 0;
        for (size_t j = 0; j < wordsize; ++j) {
            if (bit_list.size() == (i*wordsize+j)) break;
            current += (bit_list[i*wordsize+j] * (1ul<<(wordsize-1-j)));
        }
        res.push_back(current);
    }
    return res;
}
