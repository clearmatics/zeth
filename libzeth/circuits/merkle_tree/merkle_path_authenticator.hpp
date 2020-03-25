// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.hpp
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.cpp

#ifndef __ZETH_CIRCUITS_MERKLE_PATH_AUTHENTICATOR_HPP__
#define __ZETH_CIRCUITS_MERKLE_PATH_AUTHENTICATOR_HPP__

#include <libzeth/circuits/merkle_tree/merkle_path_compute.hpp>

namespace libzeth
{

// Merkle path authenticator, verifies computed root matches expected result
template<typename FieldT, typename HashTreeT>
class merkle_path_authenticator : public merkle_path_compute<FieldT, HashTreeT>
{
public:
    // Expected value of the Merkle Tree root
    const libsnark::pb_variable<FieldT> m_expected_root;

    // Boolean enforcing the comparison between the expected and
    // computed value of the Merkle Tree root
    const libsnark::pb_variable<FieldT> value_enforce;

    merkle_path_authenticator(
        libsnark::protoboard<FieldT> &pb,
        // The depth of the tree
        const size_t depth,
        // Address of the leaf to authenticate
        const libsnark::pb_variable_array<FieldT> address_bits,
        // Leaf to authenticate
        const libsnark::pb_variable<FieldT> leaf,
        // Expected root
        const libsnark::pb_variable<FieldT> expected_root,
        // Merkle Authentication path
        const libsnark::pb_variable_array<FieldT> path,
        // Boolean enforcing the comparison between the expected and
        // computed value of the Merkle Tree root
        const libsnark::pb_variable<FieldT> bool_enforce,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();

    // Returns boolean saying whether the expected and computed MT roots are
    // equal
    bool is_valid();
};

} // namespace libzeth
#include <libzeth/circuits/merkle_tree/merkle_path_authenticator.tcc>

#endif // __ZETH_CIRCUITS_MERKLE_PATH_AUTHENTICATOR_HPP__