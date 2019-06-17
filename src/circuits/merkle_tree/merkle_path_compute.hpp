// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.hpp
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.cpp

#ifndef __ZETH_MERKLE_PATH_COMPUTE_HPP__
#define __ZETH_MERKLE_PATH_COMPUTE_HPP__

#include "snarks_alias.hpp"
#include "merkle_path_selector.hpp"

namespace libzeth {

template<typename HashT, typename FieldT>
class merkle_path_compute : public libsnark::gadget<FieldT>
{
public:
    const size_t m_depth;
    const libsnark::pb_variable_array<FieldT> m_address_bits;
    const libsnark::pb_variable<FieldT> m_leaf;
    const libsnark::pb_variable_array<FieldT> m_path;

    std::vector<merkle_path_selector<FieldT>> m_selectors;
    std::vector<HashT> m_hashers;

    merkle_path_compute(
        libsnark::protoboard<FieldT> &in_pb,
        const size_t in_depth,
        const libsnark::pb_variable_array<FieldT>& in_address_bits,
        const libsnark::pb_variable<FieldT> in_leaf,
        const libsnark::pb_variable_array<FieldT>& in_path,
        const std::string &in_annotation_prefix
    );

    const libsnark::pb_variable<FieldT> result();

    void generate_r1cs_constraints();

    void generate_r1cs_witness();
};


} // libzeth

#include "merkle_path_compute.tcc"

// __ZETH_MERKLE_PATH_COMPUTE_HPP__
#endif
