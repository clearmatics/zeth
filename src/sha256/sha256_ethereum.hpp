#ifndef __SHA256_ETHEREUM_HPP__
#define __SHA256_ETHEREUM_HPP__

#include <iostream>

#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libff/common/default_types/ec_pp.hpp"
#include "libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp"

#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_components.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

// See: https://github.com/scipr-lab/libff/blob/master/libff/common/default_types/ec_pp.hpp
// We need to set the right curve as a flag during the compilation, and the right curve is going to be picked
// if we use the default_ec_pp as a FieldT`
// typedef libff::Fr<libff::default_ec_pp> FieldT;

const size_t SHA256_ETH_digest_size = 256;
const size_t SHA256_ETH_block_size = 512;

template<typename FieldT>
class sha256_ethereum: public libsnark::gadget<FieldT> {
private:
    std::shared_ptr<libsnark::block_variable<FieldT>> block1;
    std::shared_ptr<libsnark::block_variable<FieldT>> block2;
    std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<libsnark::digest_variable<FieldT>> intermediate_hash;
    std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>> hasher2;

public:
    typedef libff::bit_vector hash_value_type; // Important to define the hash_value_type as it is used in the merkle tree
    typedef libsnark::merkle_authentication_path merkle_authentication_path_type; // Same as above, this is used in the merkle tree

    sha256_ethereum(libsnark::protoboard<FieldT> &pb,
                    const size_t block_length,
                    const libsnark::block_variable<FieldT> &input_block,
                    const libsnark::digest_variable<FieldT> &output,
                    const std::string &annotation_prefix);

    void generate_r1cs_constraints(const bool ensure_output_bitness=true);
    void generate_r1cs_witness();

    static size_t get_block_len();
    static size_t get_digest_len();
    static libff::bit_vector get_hash(const libff::bit_vector &input);

    static size_t expected_constraints(const bool ensure_output_bitness);
};

// See: https://github.com/scipr-lab/libff/blob/master/libff/common/default_types/ec_pp.hpp
// We need to set the right curve as a flag during the compilation, and the right curve is going to be picked
// if we use the default_ec_pp as a FieldT`
// typedef libff::Fr<libff::default_ec_pp> FieldT;

// These functions are not methods of our gadget class
std::vector<unsigned long> bit_list_to_ints(std::vector<bool> bit_list, const size_t wordsize);
template<typename FieldT> libsnark::pb_variable_array<FieldT> from_bits(std::vector<bool> bits, libsnark::pb_variable<FieldT>& ZERO);

#include "sha256_ethereum.tcc"

#endif
