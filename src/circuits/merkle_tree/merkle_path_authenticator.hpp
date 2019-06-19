// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.hpp
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.cpp

#ifndef __ZETH_MERKLE_PATH_AUTHENTICATOR_HPP__
#define __ZETH_MERKLE_PATH_AUTHENTICATOR_HPP__

#include "snarks_alias.hpp"
#include "merkle_path_compute.hpp"

namespace libzeth {

/**
* Merkle path authenticator, verifies computed root matches expected result
*/
template<typename HashT, typename FieldT>
class merkle_path_authenticator : public merkle_path_compute<HashT, FieldT>
{
public:
    const libsnark::pb_variable<FieldT> m_expected_root;
    const libsnark::pb_variable<FieldT> value_enforce;

    merkle_path_authenticator(
        libsnark::protoboard<FieldT> &pb,
        const size_t depth,
        const libsnark::pb_variable_array<FieldT> address_bits,
        const libsnark::pb_variable<FieldT> leaf,
        const libsnark::pb_variable<FieldT> expected_root,
        const libsnark::pb_variable_array<FieldT> path,
        const std::string &annotation_prefix,
        const libsnark::pb_variable<FieldT> bool_enforce = FieldT("1")
    );

    bool is_valid();

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

} // libzeth

#include "merkle_path_authenticator.tcc"

// __ZETH_MERKLE_PATH_AUTHENTICATOR_HPP__
#endif
