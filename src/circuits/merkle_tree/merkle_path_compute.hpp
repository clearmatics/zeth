// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.hpp
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.cpp

#ifndef __ZETH_MERKLE_PATH_COMPUTE_HPP__
#define __ZETH_MERKLE_PATH_COMPUTE_HPP__

#include "snarks_alias.hpp"
#include "merkle_path_selector.hpp"

namespace libzeth {

template<typename HashTreeT, typename FieldT>
class merkle_path_compute : public libsnark::gadget<FieldT> {
public:
    const size_t depth;
    const libsnark::pb_variable_array<FieldT> address_bits; // Address of the leaf to authenticate
    const libsnark::pb_variable<FieldT> leaf; // Leaf to authenticate
    const libsnark::pb_variable_array<FieldT> path; // Merkle Authentication path

    std::vector<merkle_path_selector<FieldT>> selectors; // Gadget informing the position in the three of the computed hash and authentication node
    std::vector<HashTreeT> hashers; // Vector of hash gadgets to compute the intermediary hashes

    merkle_path_compute(
        libsnark::protoboard<FieldT> &pb,
        const size_t depth, // Depth of the tree
        const libsnark::pb_variable_array<FieldT>& address_bits, // Address of the leaf to authenticate
        const libsnark::pb_variable<FieldT> leaf, // Leaf to authenticate
        const libsnark::pb_variable_array<FieldT>& path, // Merkle Authentication path
        const std::string &annotation_prefix
    );

    void generate_r1cs_constraints();
    void generate_r1cs_witness();

    // Returns the computed root
    const libsnark::pb_variable<FieldT> result();
};

} // libzeth
#include "merkle_path_compute.tcc"

#endif // __ZETH_MERKLE_PATH_COMPUTE_HPP__
