// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.hpp
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.cpp

#ifndef __ZETH_MERKLE_PATH_SELECTOR_HPP___
#define __ZETH_MERKLE_PATH_SELECTOR_HPP___

#include "snarks_alias.hpp"
#include "depends/libsnark/libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"

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
    const libsnark::pb_variable<FieldT> input;              // The hash of the previous level or the leaf
    const libsnark::pb_variable<FieldT> pathvar;            // The authentication node of the current level
    const libsnark::pb_variable<FieldT> is_right;           // The bit of the current level from the leaf address

    libsnark::pb_variable<FieldT> left;                     // The first input of the next hash to compute
    libsnark::pb_variable<FieldT> right;                    // The seconde input of the next hash to compute

    merkle_path_selector(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable<FieldT>& input,         // The hash of the previous level or the leaf
        const libsnark::pb_variable<FieldT>& pathvar,       // The authentication node of the current level
        const libsnark::pb_variable<FieldT>& is_right,      // The bit of the current level from the leaf address
        const std::string &annotation_prefix
    );

    void generate_r1cs_constraints();

    void generate_r1cs_witness();

    // Returns the first input (left) of the next hash to compute
    const libsnark::pb_variable<FieldT>& get_left();

    // Returns the second input (right) of the next hash to compute
    const libsnark::pb_variable<FieldT>& get_right();
};

} // libzeth

#include "merkle_path_selector.tcc"

// __ZETH_MERKLE_PATH_COMPUTE_HPP__
#endif
