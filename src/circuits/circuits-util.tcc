#ifndef __ZETH_CIRCUITS_UTILS_TCC__
#define __ZETH_CIRCUITS_UTILS_TCC__

#include <vector>
#include <libsnark/gadgetlib1/pb_variable.hpp>

namespace libzeth {

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
libsnark::linear_combination<FieldT> packed_addition(libsnark::pb_variable_array<FieldT> input) {
    auto input_swapped = swap_endianness_u64(input);

    return libsnark::pb_packing_sum<FieldT>(libsnark::pb_variable_array<FieldT>(
        input_swapped.rbegin(), input_swapped.rend()
    ));
};

// From_bits() takes a vector of boolean values, and convert this vector of boolean values into a vector of
// identities in the field FieldT, where bool(0) <-> ZERO (Additive identity in FieldT), and where
// bool(1) <-> ONE (Multiplicative identity in FieldT)

/*
template<typename FieldT>
libsnark::pb_variable_array<FieldT> from_bits(std::vector<bool> bits, libsnark::pb_variable<FieldT>& ZERO)
{
    libsnark::pb_variable_array<FieldT> acc;
    for (size_t i = 0; i < bits.size(); i++) {
        bool bit = bits[i];
        acc.emplace_back(bit ? ONE : ZERO);
    }

    return acc;
}
*/

} // libzeth

#endif // __ZETH_CIRCUITS_UTILS_TCC__