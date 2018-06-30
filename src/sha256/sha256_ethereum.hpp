#ifndef __SHA256_GADGET_HPP__
#define __SHA256_GADGET_HPP__

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

typedef libff::Fr<libff::default_ec_pp> FieldT;

libsnark::pb_variable_array<FieldT> from_bits(std::vector<bool> bits, libsnark::pb_variable<FieldT>& ZERO);
std::vector<unsigned long> bit_list_to_ints(std::vector<bool> bit_list, const size_t wordsize);

class sha256_ethereum : public libsnark::gadget<FieldT> {
private:
    std::shared_ptr<libsnark::block_variable<FieldT>> block1;
    std::shared_ptr<libsnark::block_variable<FieldT>> block2;
    std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<libsnark::digest_variable<FieldT>> intermediate_hash;
    std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>> hasher2;

public:
   sha256_ethereum(
        libsnark::protoboard<FieldT> &pb,
        const size_t block_length,
        const libsnark::block_variable<FieldT> &input_block,
        const libsnark::digest_variable<FieldT> &output,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints(const bool ensure_output_bitness);
    void generate_r1cs_witness();
    static size_t get_digest_len();
    static libff::bit_vector get_hash(const libff::bit_vector &input);
    static size_t expected_constraints(const bool ensure_output_bitness);
};

#endif
