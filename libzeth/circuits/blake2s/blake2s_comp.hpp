// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_BLAKE2S_COMP_HPP__
#define __ZETH_CIRCUITS_BLAKE2S_COMP_HPP__

#include "libzeth/circuits/binary_operation.hpp"
#include "libzeth/circuits/blake2s/g_primitive.hpp"
#include "libzeth/circuits/circuits_utils.hpp"
#include "libzeth/types/bits.hpp"
#include "libzeth/util.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <math.h>

namespace libzeth
{

const size_t BLAKE2s_digest_size = 256;
const size_t BLAKE2s_block_size = 512;

/// Number of words composing the state of BLAKE2s
const size_t BLAKE2s_word_number = 16;
/// Bit-length of the words composing the state of BLAKE2s
const size_t BLAKE2s_word_size = 32;

/// BLAKE2s_256_comp is the gadget implementing the BLAKE2s
/// compression function for digests of length 256
template<typename FieldT>
class BLAKE2s_256_comp : public libsnark::gadget<FieldT>
{
private:
    // Finalization flags. See Section 2.3 of https://blake2.net/blake2.pdf
    // We do a single call to the compression function: the first block is the
    // last. Thus, f0 is set to xFFFFFFFF
    //
    // Note:
    // We use the workaround described here
    // https://stackoverflow.com/questions/32912921/whats-wrong-with-this-inline-initialization-of-stdarray
    // to initialize the const std::arrays
    const std::array<bool, BLAKE2s_word_size> flag_to_1 = {{
        1, 1, 1, 1, 1, 1, 1, 1, // FF
        1, 1, 1, 1, 1, 1, 1, 1, // FF
        1, 1, 1, 1, 1, 1, 1, 1, // FF
        1, 1, 1, 1, 1, 1, 1, 1  // FF
    }};

    // We use the sequential mode, f1 is set to x00000000
    const std::array<bool, BLAKE2s_word_size> f1 = {{
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0  // 00
    }};

    // Section 2.1 of https://blake2.net/blake2.pdf specifies that BLAKE2s has
    // 10 rounds
    static const int rounds = 10;

    // Low and High words of the offset
    std::array<std::array<bool, BLAKE2s_word_size>, 2> t;

    // Chaining values
    libsnark::digest_variable<FieldT> h;
    std::array<libsnark::pb_variable_array<FieldT>, 8> h_array;
    std::array<
        std::array<libsnark::pb_variable_array<FieldT>, BLAKE2s_word_number>,
        rounds + 1>
        v;
    std::array<
        std::array<libsnark::pb_variable_array<FieldT>, BLAKE2s_word_number>,
        rounds>
        v_temp;

    libsnark::block_variable<FieldT> input_block;
    std::array<libsnark::pb_variable_array<FieldT>, BLAKE2s_word_number> block;

    std::array<libsnark::pb_variable_array<FieldT>, 8> output_bytes;
    std::array<libsnark::pb_variable_array<FieldT>, 8> out_temp;

    // Array of mixing functions G used in each rounds in the compression
    // function
    std::array<std::vector<g_primitive<FieldT>>, rounds> g_arrays;
    std::vector<xor_gadget<FieldT>> xor_vector;

public:
    libsnark::digest_variable<FieldT> output;

    BLAKE2s_256_comp(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::digest_variable<FieldT> &h,
        const libsnark::block_variable<FieldT> &input_block,
        const libsnark::digest_variable<FieldT> &output,
        const std::string &annotation_prefix = "BLAKE2sCompression_gadget");

    // //!\\ Beware we do not check the booleaness of the input block
    // Unused ensure_output_bitness
    // This gadget ensures automatically the booleaness of the digest output
    void generate_r1cs_constraints(const bool ensure_output_bitness = true);

    // We set the flags' and counters' default value for one compression
    // function with full block length input
    void generate_r1cs_witness(
        size_t len_byte_total = 32, bool is_last_block = true);

    static size_t get_block_len();
    static size_t get_digest_len();
    static libff::bit_vector get_hash(const libff::bit_vector &input);

    static size_t expected_constraints(const bool ensure_output_bitness);

    // Helper functions to initialize the compression function parameters
    void setup_h();
    void setup_counter(size_t len_byte_total);
    void setup_v(bool is_last_block);
    void setup_mixing_gadgets();
};

} // namespace libzeth
#include "libzeth/circuits/blake2s/blake2s_comp.tcc"
#include "libzeth/circuits/blake2s/blake2s_comp_setup.tcc"

#endif // __ZETH_CIRCUITS_BLAKE2S_COMP_HPP__
