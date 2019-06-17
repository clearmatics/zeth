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
    const size_t depth;
    const libsnark::pb_variable_array<FieldT> address_bits;
    const libsnark::pb_variable<FieldT> leaf;
    const libsnark::pb_variable_array<FieldT> path;

    std::vector<merkle_path_selector<FieldT>> selectors;
    std::vector<HashT> hashers;

    merkle_path_compute(
        libsnark::protoboard<FieldT> &pb,
        const size_t depth,
        const libsnark::pb_variable_array<FieldT>& address_bits,
        const libsnark::pb_variable<FieldT> leaf,
        const libsnark::pb_variable_array<FieldT>& path,
        const std::string &annotation_prefix
    );

    const libsnark::pb_variable<FieldT> result();

    void generate_r1cs_constraints();

    void generate_r1cs_witness();
};


} // libzeth

#include "merkle_path_compute.tcc"

// __ZETH_MERKLE_PATH_COMPUTE_HPP__
#endif
