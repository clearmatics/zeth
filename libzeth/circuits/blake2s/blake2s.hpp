// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_BLAKE2S_HPP__
#define __ZETH_CIRCUITS_BLAKE2S_HPP__

#include "libzeth/circuits/binary_operation.hpp"
#include "libzeth/circuits/blake2s/blake2s_comp.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/core/bits.hpp"
#include "libzeth/core/utils.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <math.h>

namespace libzeth
{

/// BLAKE2s_256 is the gadget implementing the BLAKE2s
/// hash function for digests of length 256
template<typename FieldT> class BLAKE2s_256 : public libsnark::gadget<FieldT>
{
private:
    // Parameter block, size set to 32 bytes, fanout and depth set to serial
    // mode. See: Section 2.8 https://blake2.net/blake2.pdf Table 2
    std::array<std::array<bool, BLAKE2s_word_size>, 8> parameter_block = {
        {{
             // Digest byte length, Key byte length, Fanout, Depth
             0, 0, 1, 0, 0, 0, 0, 0, // 0x20 (32 bytes)
             0, 0, 0, 0, 0, 0, 0, 0, // 0x00 (key length)
             0, 0, 0, 0, 0, 0, 0, 1, // 0x01 (fanout 1)
             0, 0, 0, 0, 0, 0, 0, 1  // 0x01 (depth 1)
         },
         {
             // Leaf length
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0  // 00
         },
         {
             // Node offset
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0  // 00
         },
         {
             // Node offset (cont.), Node depth, Inner length
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0, // 00 (node depth)
             0, 0, 0, 0, 0, 0, 0, 0  // 00 (inner length)
         },
         {
             // Salt
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0  // 00
         },
         {
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0  // 00
         },
         {
             // Personalization
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0  // 00
         },
         {
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0, // 00
             0, 0, 0, 0, 0, 0, 0, 0  // 00
         }}};

    // See: Appendix A.2 of https://blake2.net/blake2.pdf for the specification
    // of the IV used in BLAKE2s
    std::array<std::array<bool, BLAKE2s_word_size>, 8> BLAKE2s_IV = {
        {{
             0, 1, 1, 0, 1, 0, 1, 0, // 6A
             0, 0, 0, 0, 1, 0, 0, 1, // 09
             1, 1, 1, 0, 0, 1, 1, 0, // E6
             0, 1, 1, 0, 0, 1, 1, 1  // 67
         },
         {
             1, 0, 1, 1, 1, 0, 1, 1, // BB
             0, 1, 1, 0, 0, 1, 1, 1, // 67
             1, 0, 1, 0, 1, 1, 1, 0, // AE
             1, 0, 0, 0, 0, 1, 0, 1  // 85
         },
         {
             0, 0, 1, 1, 1, 1, 0, 0, // 3C
             0, 1, 1, 0, 1, 1, 1, 0, // 6E
             1, 1, 1, 1, 0, 0, 1, 1, // F3
             0, 1, 1, 1, 0, 0, 1, 0  // 72
         },
         {
             1, 0, 1, 0, 0, 1, 0, 1, // A5
             0, 1, 0, 0, 1, 1, 1, 1, // 4F
             1, 1, 1, 1, 0, 1, 0, 1, // F5
             0, 0, 1, 1, 1, 0, 1, 0  // 3A
         },
         {
             0, 1, 0, 1, 0, 0, 0, 1, // 51
             0, 0, 0, 0, 1, 1, 1, 0, // 0E
             0, 1, 0, 1, 0, 0, 1, 0, // 52
             0, 1, 1, 1, 1, 1, 1, 1  // 7F
         },
         {
             1, 0, 0, 1, 1, 0, 1, 1, // 9B
             0, 0, 0, 0, 0, 1, 0, 1, // 05
             0, 1, 1, 0, 1, 0, 0, 0, // 68
             1, 0, 0, 0, 1, 1, 0, 0  // 8C
         },
         {
             0, 0, 0, 1, 1, 1, 1, 1, // 1F
             1, 0, 0, 0, 0, 0, 1, 1, // 83
             1, 1, 0, 1, 1, 0, 0, 1, // D9
             1, 0, 1, 0, 1, 0, 1, 1  // AB
         },
         {
             0, 1, 0, 1, 1, 0, 1, 1, // 5B
             1, 1, 1, 0, 0, 0, 0, 0, // E0
             1, 1, 0, 0, 1, 1, 0, 1, // CD
             0, 0, 0, 1, 1, 0, 0, 1  // 19
         }}};

    std::vector<libsnark::block_variable<FieldT>> block;
    // Chaining values
    std::vector<libsnark::digest_variable<FieldT>> h;

    libsnark::block_variable<FieldT> input;
    libsnark::digest_variable<FieldT> output;

    // Vector of compression functions
    std::vector<BLAKE2s_256_comp<FieldT>> BLAKE2sC_vector;

public:
    BLAKE2s_256(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::block_variable<FieldT> &input,
        const libsnark::digest_variable<FieldT> &output,
        const std::string &annotation_prefix = "blake2s_gadget");

    // //!\\ Beware we do not check the booleaness of the input block
    // Unused ensure_output_bitness
    // This gadget ensures automatically the booleaness of the digest output
    void generate_r1cs_constraints(const bool ensure_output_bitness = true);
    void generate_r1cs_witness();

    static size_t get_block_len();
    static size_t get_digest_len();
    static libff::bit_vector get_hash(const libff::bit_vector &input);

    static size_t expected_constraints(const bool ensure_output_bitness);
};

} // namespace libzeth

#include "libzeth/circuits/blake2s/blake2s.tcc"

#endif // __ZETH_CIRCUITS_BLAKE2S_HPP__
