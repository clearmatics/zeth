#ifndef __ZETH_CIRCUITS_UTILS_HPP__
#define __ZETH_CIRCUITS_UTILS_HPP__

#include <libsnark/gadgetlib1/pb_variable.hpp>

#include "snarks_alias.hpp"

namespace libzeth {

template<typename T> std::vector<bool> convert_to_binary_LE(T x, int bitlen);
template<typename T> T swap_endianness_u64(T v);
template<typename FieldT> libsnark::linear_combination<FieldT> packed_addition(libsnark::pb_variable_array<FieldT> input);
template<typename FieldT> libsnark::pb_variable_array<FieldT> from_bits(std::vector<bool> bits, libsnark::pb_variable<FieldT>& ZERO);

std::vector<unsigned long> bit_list_to_ints(std::vector<bool> bit_list, const size_t wordsize);

// pb_variable utils
template<typename FieldT> libsnark::pb_variable<FieldT> get_iv_mt(libsnark::protoboard<FieldT>& pb);
template<typename FieldT> libsnark::pb_variable<FieldT> get_iv_add(libsnark::protoboard<FieldT>& pb);
template<typename FieldT> libsnark::pb_variable<FieldT> get_iv_sn(libsnark::protoboard<FieldT>& pb);
template<typename FieldT> libsnark::pb_variable<FieldT> get_iv_pk(libsnark::protoboard<FieldT>& pb);
template<typename FieldT> libsnark::pb_variable<FieldT> get_var(libsnark::protoboard<FieldT>& pb);
template<typename FieldT> libsnark::pb_variable<FieldT> get_zero(libsnark::protoboard<FieldT>& pb);

} // libzeth
#include "circuits/circuits-util.tcc"

#endif // __ZETH_CIRCUITS_UTILS_HPP__
