#ifndef __ZETH_CIRCUITS_SHA256_ETHEREUM_HPP__
#define __ZETH_CIRCUITS_SHA256_ETHEREUM_HPP__

// DISCLAIMER:
// Content taken and adapted from:
// https://gist.github.com/kobigurk/24c25e68219df87c348f1a78db51bb52

// This gadget implements the interface of the HashT template

#include "libff/common/default_types/ec_pp.hpp"
#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp"

#include <iostream>
#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_components.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

namespace libzeth
{

const size_t SHA256_ETH_digest_size = 256;
const size_t SHA256_ETH_block_size = 512;

template<typename FieldT>
class sha256_ethereum : public libsnark::gadget<FieldT>
{
private:
    std::shared_ptr<libsnark::block_variable<FieldT>> block1;
    std::shared_ptr<libsnark::block_variable<FieldT>> block2;
    std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>>
        hasher1;
    std::shared_ptr<libsnark::digest_variable<FieldT>> intermediate_hash;
    std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>>
        hasher2;

public:
    // Important to define the hash_value_type as it is used in the merkle tree
    typedef libff::bit_vector hash_value_type;
    // Same as above, this is used in the merkle tree
    typedef libsnark::merkle_authentication_path
        merkle_authentication_path_type;

    sha256_ethereum(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::block_variable<FieldT> &input_block,
        const libsnark::digest_variable<FieldT> &output,
        const std::string &annotation_prefix = "sha256_ethereum");

    void generate_r1cs_constraints(const bool ensure_output_bitness = true);
    void generate_r1cs_witness();

    static size_t get_block_len();
    static size_t get_digest_len();
    static libff::bit_vector get_hash(const libff::bit_vector &input);

    static size_t expected_constraints(const bool ensure_output_bitness);
};

} // namespace libzeth
#include "circuits/sha256/sha256_ethereum.tcc"

#endif // __ZETH_CIRCUITS_SHA256_ETHEREUM_HPP__
