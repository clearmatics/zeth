#ifndef __ZETH_CIRCUITS_CIRCUITS_UTILS_HPP__
#define __ZETH_CIRCUITS_CIRCUITS_UTILS_HPP__

#include "types/bits.hpp"

#include <libsnark/gadgetlib1/pb_variable.hpp>

namespace libzeth
{

template<typename T> std::vector<bool> convert_to_binary_LE(T x, int bitlen);
template<typename T> T swap_endianness_u64(T v);
template<typename FieldT>
libsnark::linear_combination<FieldT> packed_addition(
    libsnark::pb_variable_array<FieldT> input);
template<typename FieldT>
libsnark::pb_variable_array<FieldT> from_bits(
    std::vector<bool> bits, libsnark::pb_variable<FieldT> &ZERO);
template<typename FieldT, size_t BitLen>
std::array<FieldT, BitLen> binary_field_addition_no_carry(
    std::array<FieldT, BitLen> A, std::array<FieldT, BitLen> B);
template<typename FieldT, size_t BitLen>
std::array<FieldT, BitLen> binary_field_xor(
    std::array<FieldT, BitLen> A, std::array<FieldT, BitLen> B);
template<typename FieldT> std::vector<FieldT> convert_to_binary(size_t n);
void insert_bits256(std::vector<bool> &into, bits256 from);
void insert_bits64(std::vector<bool> &into, bits64 from);
std::vector<unsigned long> bit_list_to_ints(
    std::vector<bool> bit_list, const size_t wordsize);

} // namespace libzeth
#include "circuits/circuits-utils.tcc"

#endif // __ZETH_CIRCUITS_CIRCUITS_UTILS_HPP__