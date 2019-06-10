#ifndef __ZETH_CIRCUITS_UTILS_TCC__
#define __ZETH_CIRCUITS_UTILS_TCC__

#include <vector>
#include <libsnark/gadgetlib1/pb_variable.hpp>

namespace libzeth {

// This define directive is useless/redundant, as ONE is defined here:
// libsnark/gadgetlib1/pb_variable.hpp#74
#define ONE libsnark::pb_variable<FieldT>(0)
//
// We know that a pb_variable takes an index in the constructor:
// See: libsnark/gadgetlib1/pb_variable.hpp#29
// Then the pb_variable can be allocated on the protoboard
// See here for the allocation function: libsnark/gadgetlib1/pb_variable.tcc#19
// This function calls the allocation function of the protoboard: libsnark/gadgetlib1/protoboard.tcc#38
// This function basically allocates the variable on the protoboard at the index defined by the variable
// "next_free_var". It then returns the index the variable was allocated at, and, we can see in
// libsnark/gadgetlib1/pb_variable.tcc#19 that the index of the variable is given by the index where
// the variable was allocated on the protoboard.
// MOREOVER, we see in: libsnark/gadgetlib1/protoboard.tcc#19 (the constructor of the protoboard)
// that "next_free_var = 1;" to account for constant 1 term. Thus, the variable at index
// 0 on the protoboard is the constant_term variable, which value is FieldT::one()
// (which basically is the multiplicative identity of the field FieldT)
// Thus we are safe here. The ONE is well equal to the value FieldT::one()

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

/*
 * This function reverses the byte endianness
 *
 *  Example input/output:
 *
 *  Before swap (in):  After Swap (out):
 *    0011 0111         0000 0000
 *    1000 0010         0000 0000
 *    1101 1010         1001 0000
 *    1100 1110         1001 1101
 *    1001 1101         1100 1110
 *    1001 0000         1101 1010
 *    0000 0000         1000 0010
 *    0000 0000         0011 0111
**/
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
};

template<typename FieldT>
libsnark::linear_combination<FieldT> packed_addition(libsnark::pb_variable_array<FieldT> inputs) {
    // We use `inputs.rbegin(), inputs.rend()` otherwise the resulting linear combination is
    // built by interpreting our bit string as little endian. Thus here, we make sure our binary
    // string is interpreted correctly.
    return libsnark::pb_packing_sum<FieldT>(libsnark::pb_variable_array<FieldT>(
        inputs.rbegin(), inputs.rend()
    ));
};

// Takes a vector of boolean values, and convert this vector of boolean values into a vector of
// FieldT::zero() and FieldT:one()
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


// Variable maker functions: taken from https://github.com/HarryR/ethsnarks/blob/master/src/utils.hpp
inline const VariableT make_variable( ProtoboardT &in_pb, const std::string &annotation ){
    VariableT x;
    x.allocate(in_pb, annotation);
    return x;
}

inline const VariableT make_variable( ProtoboardT &in_pb, const FieldT value, const std::string &annotation )
{
    VariableT x;
    x.allocate(in_pb, annotation);
    in_pb.val(x) = value;
    return x;
}

const VariableArrayT make_var_array( ProtoboardT &in_pb, size_t n, const std::string &annotation )
{
    VariableArrayT x;
    x.allocate(in_pb, n, annotation);
    return x;
}

} // libzeth

#endif // __ZETH_CIRCUITS_UTILS_TCC__
