#ifndef __ZETH_CIRCUITS_UTILS_HPP__
#define __ZETH_CIRCUITS_UTILS_HPP__

#include <libsnark/gadgetlib1/pb_variable.hpp>
#include "types/bits.hpp"

#include "snarks_alias.hpp"

namespace libzeth {

template<typename T> std::vector<bool> convert_to_binary_LE(T x, int bitlen);
template<typename T> T swap_endianness_u64(T v);
template<typename FieldT> libsnark::linear_combination<FieldT> packed_addition(libsnark::pb_variable_array<FieldT> input);
template<typename FieldT> libsnark::pb_variable_array<FieldT> from_bits(std::vector<bool> bits, libsnark::pb_variable<FieldT>& ZERO);

void insert_bits256(std::vector<bool>& into, bits256 from);
void insert_bits64(std::vector<bool>& into, bits64 from);
std::vector<unsigned long> bit_list_to_ints(std::vector<bool> bit_list, const size_t wordsize);

const VariableT make_variable( ProtoboardT &in_pb, const std::string &annotation );
const VariableT make_variable( ProtoboardT &in_pb, const FieldT value, const std::string &annotation );
const VariableArrayT make_var_array( ProtoboardT &in_pb, size_t n, const std::string &annotation );

} // libzeth
#include "circuits/circuits-util.tcc"

#endif // __ZETH_CIRCUITS_UTILS_HPP__
