// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.hpp
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.cpp

#ifndef __ZETH_MERKLE_PATH_AUTHENTICATOR_HPP__
#define __ZETH_MERKLE_PATH_AUTHENTICATOR_HPP__

#include "snarks_alias.hpp"
#include "merkle_path_compute.hpp"

namespace libzeth {

/*
 * Merkle path authenticator, verifies computed root matches expected result
**/
template<typename HashTreeT, typename FieldT>
class merkle_path_authenticator : public merkle_path_compute<HashTreeT, FieldT> {
public:
    const libsnark::pb_variable<FieldT> m_expected_root; // Expected value of the Merkle Tree root
    const libsnark::pb_variable<FieldT> value_enforce; // Boolean enforcing the comparison between the expected and computed value of the Merkle Tree root

    merkle_path_authenticator(
        libsnark::protoboard<FieldT> &pb,
        const size_t depth, // The depth of the tree
        const libsnark::pb_variable_array<FieldT> address_bits, // Address of the leaf to authenticate
        const libsnark::pb_variable<FieldT> leaf, // Leaf to authenticate
        const libsnark::pb_variable<FieldT> expected_root, // Expected root
        const libsnark::pb_variable_array<FieldT> path, // Merkle Authentication path
        const libsnark::pb_variable<FieldT> bool_enforce, // Boolean enforcing the comparison between the expected and computed value of the Merkle Tree root
        const std::string &annotation_prefix
    );

    void generate_r1cs_constraints();
    void generate_r1cs_witness();

    // Returns boolean saying whether the expected and computed MT roots are equal
    bool is_valid();
};

} // libzeth
#include "merkle_path_authenticator.tcc"

#endif // __ZETH_MERKLE_PATH_AUTHENTICATOR_HPP__