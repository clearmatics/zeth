#ifndef __ZETH_CIRCUITS_UTILS_HPP__
#define __ZETH_CIRCUITS_UTILS_HPP__

#include <libsnark/gadgetlib1/pb_variable.hpp>

#include "types/bits.hpp"

namespace libzeth {

template<typename T> std::vector<bool> convert_to_binary_LE(T x, int bitlen);
template<typename T> T swap_endianness_u64(T v);
template<typename FieldT> libsnark::linear_combination<FieldT> packed_addition(libsnark::pb_variable_array<FieldT> input);
template<typename FieldT> libsnark::pb_variable_array<FieldT> from_bits(std::vector<bool> bits, libsnark::pb_variable<FieldT>& ZERO);

void insert_bits256(std::vector<bool>& into, bits256 from);
void insert_bits64(std::vector<bool>& into, bits64 from);
std::vector<unsigned long> bit_list_to_ints(std::vector<bool> bit_list, const size_t wordsize);


template<typename FieldT>
class reverse_packing_gadget : public gadget<FieldT> {
private:
    /* no internal variables */
public:
    const pb_linear_combination_array<FieldT> bits;
    const pb_linear_combination<FieldT> packed;

    reverse_packing_gadget(protoboard<FieldT> &pb,
                   const pb_linear_combination_array<FieldT> &bits,
                   const pb_linear_combination<FieldT> &packed,
                   const std::string &annotation_prefix="") :
        gadget<FieldT>(pb, annotation_prefix), bits(bits), packed(packed) {}

    void generate_r1cs_constraints(const bool enforce_bitness);
    /* adds constraint result = \sum  bits[i] * 2^i */

    void generate_r1cs_witness_from_packed();
    void generate_r1cs_witness_from_bits();
};

} // libzeth
#include "circuits/circuits-util.tcc"

#endif // __ZETH_CIRCUITS_UTILS_HPP__