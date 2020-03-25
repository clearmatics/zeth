// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.hpp
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.cpp

#ifndef __ZETH_CIRCUITS_MERKLE_PATH_COMPUTE_HPP__
#define __ZETH_CIRCUITS_MERKLE_PATH_COMPUTE_HPP__

#include <libzeth/circuits/merkle_tree/merkle_path_selector.hpp>

namespace libzeth
{

template<typename FieldT, typename HashTreeT>
class merkle_path_compute : public libsnark::gadget<FieldT>
{
public:
    const size_t depth;
    // Address of the leaf to authenticate
    const libsnark::pb_variable_array<FieldT> address_bits;
    // Leaf to authenticate
    const libsnark::pb_variable<FieldT> leaf;
    // Merkle Authentication path
    const libsnark::pb_variable_array<FieldT> path;

    // Gadget informing the position in the three of the computed
    // hash and authentication node
    std::vector<merkle_path_selector<FieldT>> selectors;
    // Vector of hash gadgets to compute the intermediary hashes
    std::vector<HashTreeT> hashers;

    merkle_path_compute(
        libsnark::protoboard<FieldT> &pb,
        // Depth of the tree
        const size_t depth,
        // Address of the leaf to authenticate
        const libsnark::pb_variable_array<FieldT> &address_bits,
        // Leaf to authenticate
        const libsnark::pb_variable<FieldT> leaf,
        // Merkle Authentication path
        const libsnark::pb_variable_array<FieldT> &path,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();

    // Returns the computed root
    const libsnark::pb_variable<FieldT> result();
};

} // namespace libzeth
#include <libzeth/circuits/merkle_tree/merkle_path_compute.tcc>

#endif // __ZETH_CIRCUITS_MERKLE_PATH_COMPUTE_HPP__