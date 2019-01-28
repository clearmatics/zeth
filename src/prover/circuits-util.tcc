#ifndef __ZETH_CIRCUITS_UTILS_TCC__
#define __ZETH_CIRCUITS_UTILS_TCC__

#include <libsnark/gadgetlib1/pb_variable.hpp>
#include "utils.hpp"
#include "src/bits256.tcc"
#include "src/util.hpp"

template<typename FieldT>
libsnark::pb_variable_array<FieldT> from_bits(std::vector<bool> bits, libsnark::pb_variable<FieldT>& ZERO) {
    pb_variable_array<FieldT> acc;

    BOOST_FOREACH(bool bit, bits) {
        acc.emplace_back(bit ? ONE : ZERO);
    }

    return acc;
};

// Converts a given number encoded on bitlen bits into a
// binary string of lentgh bitlen.
// The encoding is Little Endian.
template<typename T>
std::vector<bool> convert_to_binary_LE(T x, int bitlen) {
    std::vector<bool> ret;
    for(int i = 0; i < bitlen; i++){
        if (x&1)
            ret.push_back(1);
        else
            ret.push_back(0);
        x>>=1;
    }
    return ret;
};

void insert_bits256(std::vector<bool>& into, bits256 from) {
    std::vector<bool> blob = get_vector_from_bits256(from);
    into.insert(into.end(), blob.begin(), blob.end());
};

void insert_bits64(std::vector<bool>& into, bits64 from) {
    std::vector<bool> num = get_vector_from_bits64(from);
    into.insert(into.end(), num.begin(), num.end());
};

template<typename T>
T swap_endianness_u64(T v) {
    if (v.size() != 64) {
        throw std::length_error("invalid bit length for 64-bit unsigned integer");
    }

    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 8; j++) {
            std::swap(v[i*8 + j], v[((7-i)*8)+j]);
        }
    }

    return v;
}

template<typename FieldT>
libsnark::linear_combination<FieldT> packed_addition(pb_variable_array<FieldT> input) {
    auto input_swapped = swap_endianness_u64(input);

    return pb_packing_sum<FieldT>(pb_variable_array<FieldT>(
        input_swapped.rbegin(), input_swapped.rend()
    ));
};

#endif // __ZETH_CIRCUITS_UTILS_TCC__