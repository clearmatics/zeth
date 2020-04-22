// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_BLAKE2S_TCC__
#define __ZETH_CIRCUITS_BLAKE2S_TCC__

#include "libzeth/circuits/blake2s/blake2s.hpp"

namespace libzeth
{

/// This gadget implements the interface of the HashT template
template<typename FieldT>
BLAKE2s_256<FieldT>::BLAKE2s_256(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::block_variable<FieldT> &input,
    const libsnark::digest_variable<FieldT> &output,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , input(input)
    , output(output)
{
    size_t nb_blocks = libff::div_ceil(input.bits.size(), BLAKE2s_block_size);

    // Allocate and format the 16 input block variable
    for (size_t i = 0; i < nb_blocks; i++) {
        libsnark::digest_variable<FieldT> temp_digest(
            pb, BLAKE2s_digest_size, FMT(this->annotation_prefix, " h_%zu", i));
        h.emplace_back(temp_digest);

        libsnark::block_variable<FieldT> temp_block(
            pb,
            BLAKE2s_block_size,
            FMT(this->annotation_prefix, " block_%zu", i));
        block.emplace_back(temp_block);
    }

    for (size_t i = 0; i < nb_blocks - 1; i++) {
        BLAKE2sC_vector.emplace_back(BLAKE2s_256_comp<FieldT>(
            pb,
            h[i],
            block[i],
            h[i + 1],
            FMT(this->annotation_prefix, " BLAKE2sC_%zu", i)));
    }
    BLAKE2sC_vector.emplace_back(BLAKE2s_256_comp<FieldT>(
        pb,
        h[nb_blocks - 1],
        block[nb_blocks - 1],
        output,
        FMT(this->annotation_prefix, " BLAKE2sC_%zu", nb_blocks - 1)));
};

template<typename FieldT>
void BLAKE2s_256<FieldT>::generate_r1cs_constraints(
    const bool ensure_output_bitness)
{
    for (auto &gadget : BLAKE2sC_vector) {
        gadget.generate_r1cs_constraints(ensure_output_bitness);
    }
};

template<typename FieldT> void BLAKE2s_256<FieldT>::generate_r1cs_witness()
{
    // Format two 256-bit long big endian inputs into one 512 long little endian
    // input (with padding if necessary)
    size_t input_size = input.bits.size();
    size_t nb_blocks = libff::div_ceil(input_size, BLAKE2s_block_size);
    // We do not use block_size because the value might not be entered
    // (c.f. block_variable<FieldT>::block_variable(
    //     protoboard<FieldT> &pb,
    //     const std::vector<pb_variable_array<FieldT>> &parts,
    //     const std::string &annotation_prefix))

    // Push the block variable in local variable to be padded
    std::vector<FieldT> padded_input;
    for (size_t i = 0; i < input_size; i++) {
        padded_input.push_back(this->pb.val(input.bits[i]));
    }

    // [SANITY CHECK] Pad if necessary (if input_size % BLAKE2s_block_size != 0)
    size_t to_pad = input_size % BLAKE2s_block_size;
    if (to_pad != 0) {
        for (size_t i = 0; i < BLAKE2s_block_size - to_pad; i++) {
            padded_input.push_back(FieldT("0"));
        }
    }

    for (size_t i = 0; i < nb_blocks; i++) {
        std::vector<FieldT> temp_vector(
            padded_input.begin() + BLAKE2s_block_size * i,
            padded_input.begin() + BLAKE2s_block_size * (i + 1));
        block[i].bits.fill_with_field_elements(this->pb, temp_vector);
    }

    // See: Appendix A.1 of https://blake2.net/blake2.pdf
    std::vector<bool> h_bits;
    for (size_t i = 0; i < 8; i++) {
        std::array<bool, BLAKE2s_word_size> pb_swapped =
            swap_byte_endianness(parameter_block[i]);
        std::vector<bool> h_part =
            get_vector_from_bits32(binary_xor(pb_swapped, BLAKE2s_IV[i]));
        h_bits.insert(h_bits.end(), h_part.begin(), h_part.end());
    }
    h[0].bits.fill_with_bits(this->pb, h_bits);

    for (size_t i = 0; i < nb_blocks - 1; i++) {
        BLAKE2sC_vector[i].generate_r1cs_witness(
            libff::div_ceil((i + 1) * BLAKE2s_block_size, BYTE_LEN), false);
    }
    BLAKE2sC_vector[nb_blocks - 1].generate_r1cs_witness(
        libff::div_ceil(input_size, BYTE_LEN), true);
};

template<typename FieldT> size_t BLAKE2s_256<FieldT>::get_digest_len()
{
    return BLAKE2s_digest_size;
}

template<typename FieldT> size_t BLAKE2s_256<FieldT>::get_block_len()
{
    return BLAKE2s_block_size;
}

/// This function returns the number of gates necessary
/// to implement the compression function of blake2s
/// To obtain the number of gates for blake2s hash,
/// the output of the function must be multiplied by
/// the number of input blocks.
template<typename FieldT>
size_t BLAKE2s_256<FieldT>::expected_constraints(
    const bool ensure_output_bitness)
{
    libff::UNUSED(ensure_output_bitness);
    return 21472;
}

template<typename FieldT>
libff::bit_vector BLAKE2s_256<FieldT>::get_hash(const libff::bit_vector &input)
{
    libsnark::protoboard<FieldT> pb;

    libsnark::block_variable<FieldT> input_block(
        pb, input.size(), "input_block");
    libsnark::digest_variable<FieldT> output_variable(
        pb, BLAKE2s_digest_size, "output_variable");
    BLAKE2s_256<FieldT> blake2s_hasher(
        pb, input_block, output_variable, "blake2s_hasher_gadget");

    input_block.generate_r1cs_witness(input);
    blake2s_hasher.generate_r1cs_witness();

    return output_variable.get_digest();
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_BLAKE2S_TCC__
