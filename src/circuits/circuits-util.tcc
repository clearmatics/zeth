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

template<typename FieldT>
libsnark::pb_variable<FieldT> get_iv_mt(libsnark::protoboard<FieldT>& pb) {
    libsnark::pb_variable<FieldT> iv;
    iv.allocate(pb, "iv");
    // iv = sha3("Clearmatics")
    pb.val(iv) = FieldT("14220067918847996031108144435763672811050758065945364308986253046354060608451");
    return iv;
}


template<typename FieldT>
libsnark::pb_variable<FieldT> get_iv_cm(libsnark::protoboard<FieldT>& pb) {
    libsnark::pb_variable<FieldT> iv;
    iv.allocate(pb, "iv_cm");
    // iv = sha3("Clearmatics_cm")
    pb.val(iv) = FieldT("91858436274657200763343017909794347500533039453032596640521388943016484459476");
    return iv;
}


template<typename FieldT>
libsnark::pb_variable<FieldT> get_iv_add(libsnark::protoboard<FieldT>& pb) {
    libsnark::pb_variable<FieldT> iv;
    iv.allocate(pb, "iv_add");
    // iv = sha3("Clearmatics_add")
    pb.val(iv) = FieldT("7655352919458297598499032567765357605187604397960652899494713742188031353302");
    return iv;
}


template<typename FieldT>
libsnark::pb_variable<FieldT> get_iv_sn(libsnark::protoboard<FieldT>& pb) {
    libsnark::pb_variable<FieldT> iv;
    iv.allocate(pb, "iv_sn");
    // iv = sha3("Clearmatics_sn")
    pb.val(iv) = FieldT("38594890471543702135425523844252992926779387339253565328142220201141984377400");
    return iv;
}


template<typename FieldT>
libsnark::pb_variable<FieldT> get_iv_pk(libsnark::protoboard<FieldT>& pb) {
    libsnark::pb_variable<FieldT> iv;
    iv.allocate(pb, "iv_pk");
    // iv = sha3("Clearmatics_pk")
    pb.val(iv) = FieldT("20715549373167656640519441333099474211916836972862576858009333815040496998894");
    return iv;
}

template<typename FieldT>
libsnark::pb_variable<FieldT> get_var(libsnark::protoboard<FieldT>& pb, const std::string &annotation) {
    libsnark::pb_variable<FieldT> var;
    var.allocate(pb, annotation);
    return var;
}

template<typename FieldT>
libsnark::pb_variable<FieldT> get_var(libsnark::protoboard<FieldT>& pb, FieldT value, const std::string &annotation) {
    libsnark::pb_variable<FieldT> var;
    var.allocate(pb, annotation);
    pb.val(var) = value;
    return var;
}

} // libzeth

#endif // __ZETH_CIRCUITS_UTILS_TCC__
