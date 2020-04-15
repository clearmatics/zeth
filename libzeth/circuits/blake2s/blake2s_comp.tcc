// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_BLAKE2s_COMP_TCC__
#define __ZETH_CIRCUITS_BLAKE2s_COMP_TCC__

namespace libzeth
{

// This gadget implements the interface of the HashT template
template<typename FieldT>
BLAKE2s_256_comp<FieldT>::BLAKE2s_256_comp(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::digest_variable<FieldT> &h,
    const libsnark::block_variable<FieldT> &input_block,
    const libsnark::digest_variable<FieldT> &output,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , h(h)
    , input_block(input_block)
    , output(output)
{
    // Allocate and format the 16 input block variable
    for (size_t i = 0; i < BLAKE2s_word_number; i++) {
        block[i].allocate(
            pb,
            BLAKE2s_word_size,
            FMT(this->annotation_prefix, " block_%zu", i));
    }

    // Allocate the init state variables and output bytes (before swapping
    // endianness and appending)
    for (size_t i = 0; i < 8; i++) {
        h_array[i].allocate(
            this->pb,
            BLAKE2s_word_size,
            FMT(this->annotation_prefix, " h_%zu", i));

        out_temp[i].allocate(
            pb,
            BLAKE2s_word_size,
            FMT(this->annotation_prefix, " out_temp_%zu", i));

        output_bytes[i].allocate(
            pb,
            BLAKE2s_word_size,
            FMT(this->annotation_prefix, " output_byte_%zu", i));
    }

    // Allocate the state variables
    for (size_t i = 0; i < rounds + 1; i++) {
        for (size_t j = 0; j < BLAKE2s_word_number; j++) {
            v[i][j].allocate(
                this->pb,
                BLAKE2s_word_size,
                FMT(this->annotation_prefix, " v_%zu", i * rounds + j));
        }
    }
    for (size_t i = 0; i < rounds; i++) {
        for (size_t j = 0; j < BLAKE2s_word_number; j++) {
            v_temp[i][j].allocate(
                this->pb,
                BLAKE2s_word_size,
                FMT(this->annotation_prefix, " v_temp_%zu", i * rounds + j));
        }
    }

    // Set up the g_primitive gadgets used in the compression function
    setup_mixing_gadgets();
};

template<typename FieldT>
void BLAKE2s_256_comp<FieldT>::generate_r1cs_constraints(
    const bool ensure_output_bitness)
{
    libff::UNUSED(ensure_output_bitness);

    for (size_t i = 0; i < rounds; i++) {
        for (auto &gadget : g_arrays[i]) {
            gadget.generate_r1cs_constraints();
        }
    }

    for (auto &gadget : xor_vector) {
        gadget.generate_r1cs_constraints();
    }
};

template<typename FieldT>
void BLAKE2s_256_comp<FieldT>::generate_r1cs_witness(
    size_t len_byte_total, bool is_last_block)
{
    // Format two 256-bit long big endian inputs into one 512 long little endian
    // input (with padding if necessary)
    size_t input_size = input_block.bits.size();
    // We do not use block_size because the value might not be entered
    // (c.f. block_variable<FieldT>::block_variable(protoboard<FieldT> &pb,
    //                                   const
    //                                   std::vector<pb_variable_array<FieldT>>
    //                                   &parts, const std::string
    //                                   &annotation_prefix))

    // Push the block variable in local to be swapped
    std::vector<FieldT> padded_input;
    for (size_t i = 0; i < input_size; i++) {
        padded_input.push_back(this->pb.val(input_block.bits[i]));
    }

    // [SANITY CHECK] Pad if necessary (if input_size < BLAKE2s_block_size)
    for (size_t i = 0; i < BLAKE2s_block_size - input_size; i++) {
        padded_input.push_back(FieldT("0"));
    }

    // Allocate and format the 16 input block variable
    for (size_t i = 0; i < BLAKE2s_word_number; i++) {
        std::vector<FieldT> temp_vector(
            padded_input.begin() + BLAKE2s_word_size * i,
            padded_input.begin() + BLAKE2s_word_size * (i + 1));
        temp_vector = swap_byte_endianness(temp_vector);
        block[i].fill_with_field_elements(this->pb, temp_vector);
    }

    BLAKE2s_256_comp<FieldT>::setup_h();
    BLAKE2s_256_comp<FieldT>::setup_counter(len_byte_total);
    BLAKE2s_256_comp<FieldT>::setup_v(is_last_block);

    for (size_t i = 0; i < rounds; i++) {
        for (auto &gadget : g_arrays[i]) {
            gadget.generate_r1cs_witness();
        }
    }

    // TODO: batch equality constraints (should save ~200 constraints (~1%))

    for (auto &gadget : xor_vector) {
        gadget.generate_r1cs_witness();
    }

    // Retrieve values, swap endiannes of each bit32 and append them to get
    // final output
    std::vector<FieldT> output_conversion;
    for (size_t i = 0; i < 8; i++) {
        std::vector<FieldT> output_byte_value =
            output_bytes[i].get_vals(this->pb);

        // We swap to big endian if it is the last call.
        if (is_last_block) {
            output_byte_value = swap_byte_endianness(output_byte_value);
        }
        output_conversion.insert(
            output_conversion.end(),
            output_byte_value.begin(),
            output_byte_value.end());
    }

    output.bits.fill_with_field_elements(this->pb, output_conversion);
};

template<typename FieldT> size_t BLAKE2s_256_comp<FieldT>::get_digest_len()
{
    return BLAKE2s_digest_size;
}

template<typename FieldT> size_t BLAKE2s_256_comp<FieldT>::get_block_len()
{
    return BLAKE2s_block_size;
}

template<typename FieldT>
size_t BLAKE2s_256_comp<FieldT>::expected_constraints(
    const bool ensure_output_bitness)
{
    libff::UNUSED(ensure_output_bitness);
    return 21472;
    // ~38.89% of sha256_ethereum
}

template<typename FieldT>
libff::bit_vector BLAKE2s_256_comp<FieldT>::get_hash(
    const libff::bit_vector &input)
{
    libsnark::protoboard<FieldT> pb;

    libsnark::block_variable<FieldT> input_block(
        pb, BLAKE2s_block_size, "input_block");
    libsnark::digest_variable<FieldT> output_variable(
        pb, BLAKE2s_digest_size, "output_variable");
    BLAKE2s_256_comp<FieldT> blake2s_hasher(
        pb, input_block, output_variable, "blake2s_hasher_gadget");

    input_block.generate_r1cs_witness(input);
    blake2s_hasher.generate_r1cs_witness();

    return output_variable.get_digest();
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_BLAKE2s_COMP_TCC__