// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.hpp
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.cpp

#ifndef __ZETH_MERKLE_PATH_SELECTOR_HPP___
#define __ZETH_MERKLE_PATH_SELECTOR_HPP___

#include "snarks_alias.hpp"

/**
* Depending on the address bit, output the correct left/right inputs
* for the merkle path authentication hash
*
* 0 = left
* 1 = right
*
* There are two variables which make up each element of the path,
* the `input` and the `pathvar`, the input is the leaf or the
* output from the last hash, and the path var is part of the merkle
* tree path.
*
* The `is_right` parameter decides if the `input` is on the left or
* right of the hash. These are decided in-circuit using the following
* method:
*
* Left:
*  ((1-is_right) * input) + (is_right * pathvar)
*
* Right:
*  (is_right * input) + ((1 - is_right) * pathvar)
*
* Each component is split into a & b sides, then added together
* so the correct variable ends up in the right or left hand side.
*/

namespace libzeth {

template<typename FieldT>
class merkle_path_selector : public libsnark::gadget<FieldT>
{
public:
    libsnark::pb_variable<FieldT> m_input;
    const libsnark::pb_variable<FieldT> m_pathvar;
    const libsnark::pb_variable<FieldT> m_is_right;

    libsnark::pb_variable<FieldT> m_left_a;
    libsnark::pb_variable<FieldT> m_left_b;
    libsnark::pb_variable<FieldT> m_left;

    libsnark::pb_variable<FieldT> m_right_a;
    libsnark::pb_variable<FieldT> m_right_b;
    libsnark::pb_variable<FieldT> m_right;

    merkle_path_selector(
        libsnark::protoboard<FieldT> &in_pb,
        const libsnark::pb_variable<FieldT>& in_input,
        const libsnark::pb_variable<FieldT>& in_pathvar,
        const libsnark::pb_variable<FieldT>& in_is_right,
        const std::string &in_annotation_prefix
    );

    void generate_r1cs_constraints();

    void generate_r1cs_witness();

    const libsnark::pb_variable<FieldT>& left();

    const libsnark::pb_variable<FieldT>& right();
};

template<typename FieldT>
const libsnark::pb_variable_array<FieldT> merkle_tree_IVs (libsnark::protoboard<FieldT> &in_pb);

} // libzeth

#include "merkle_path_selector.tcc"

// __ZETH_MERKLE_PATH_COMPUTE_HPP__
#endif
