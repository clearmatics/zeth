// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_BLAKE2S_COMP_SETUP_TCC__
#define __ZETH_CIRCUITS_BLAKE2S_COMP_SETUP_TCC__

#include "libzeth/circuits/blake2s/blake2s_comp.hpp"

namespace libzeth
{

namespace
{

// Finalization flags. See Section 2.3 of https://blake2.net/blake2.pdf
// We do a single call to the compression function: the first block is the
// last. Thus, f0 is set to xFFFFFFFF
//
// Note:
// We use the workaround described here
// https://stackoverflow.com/questions/32912921/whats-wrong-with-this-inline-initialization-of-stdarray
// to initialize the const std::arrays
static const std::array<bool, BLAKE2s_word_size> flag_to_1 = {{
    1, 1, 1, 1, 1, 1, 1, 1, // FF
    1, 1, 1, 1, 1, 1, 1, 1, // FF
    1, 1, 1, 1, 1, 1, 1, 1, // FF
    1, 1, 1, 1, 1, 1, 1, 1  // FF
}};

// See: Appendix A.1 of https://blake2.net/blake2.pdf for the specification
// of the permutations used in BLAKE2s
static const std::array<std::array<uint8_t, 16>, 10> sigma = {
    {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
     {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
     {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
     {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
     {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
     {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
     {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
     {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
     {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
     {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}}};

} // namespace

template<typename FieldT>
const std::array<std::array<bool, BLAKE2s_word_size>, 8>
    BLAKE2s_256_comp<FieldT>::BLAKE2s_IV = {
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

template<typename FieldT> void BLAKE2s_256_comp<FieldT>::setup_h()
{
    std::vector<bool> bits = h.get_digest();
    // See: Appendix A.1 of https://blake2.net/blake2.pdf
    for (size_t i = 0; i < 8; i++) {
        std::vector<bool> temp_vector(
            bits.begin() + BLAKE2s_word_size * i,
            bits.begin() + BLAKE2s_word_size * (i + 1));
        h_array[i].fill_with_bits(this->pb, temp_vector);
    }
}

template<typename FieldT>
void BLAKE2s_256_comp<FieldT>::setup_counter(size_t len_byte_total)
{
    // len_byte_total represents the BYTE length all the input blocks
    // compressed so far, up to 2^64 - 1 bytes for blake2s
    std::vector<bool> length_bits = bit_vector_from_size_t_be(len_byte_total);
    size_t bit_size = length_bits.size();
    size_t padding = 64 - bit_size;

    // Initialize the low word of the offset
    t[0] = {
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0  // 00
    };
    for (size_t i = 0; int(i) < std::min(int(BLAKE2s_word_size), int(bit_size));
         i++) {
        t[0][BLAKE2s_word_size - i - 1] = length_bits[bit_size - i - 1];
    }

    // Initialize the high word of the offset
    t[1] = {
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0  // 00
    };
    // If we hash more that 2^32 bytes, then set the high word of the offset
    // accordingly
    if (bit_size > BLAKE2s_word_size) {
        for (size_t i = 0; i < bit_size - BLAKE2s_word_size; i++) {
            t[1][padding + i] = length_bits[i];
        }
    }
}

/// setup_v initializes the internal state matrix as documented
/// Appendix A.1 https://blake2.net/blake2.pdf
template<typename FieldT>
void BLAKE2s_256_comp<FieldT>::setup_v(bool is_last_block)
{
    // [v_0, ..., v_7] = [h_0, ..., h_7]
    for (size_t i = 0; i < 8; i++) {
        v[0][i].fill_with_bits(this->pb, h_array[i].get_bits(this->pb));
    }

    // [v_8, v_9, v_10, v_11] = [IV_0, IV_1, IV_2, IV_3]
    for (size_t i = 8; i < 12; i++) {
        std::vector<bool> temp_vector(
            BLAKE2s_IV[i - 8].begin(), BLAKE2s_IV[i - 8].end());
        v[0][i].fill_with_bits(this->pb, temp_vector);
    }

    // v_12 = t0 XOR IV_4
    std::array<bool, 32> temp_xored = bits_xor(BLAKE2s_IV[4], t[0]);
    std::vector<bool> temp_vector12(temp_xored.begin(), temp_xored.end());
    v[0][12].fill_with_bits(this->pb, temp_vector12);

    // v_13 = t1 XOR IV_5
    temp_xored = bits_xor(BLAKE2s_IV[5], t[1]);
    std::vector<bool> temp_vector13(temp_xored.begin(), temp_xored.end());
    v[0][13].fill_with_bits(this->pb, temp_vector13);

    // v_14 = f0 XOR IV_6
    temp_xored = BLAKE2s_IV[6];
    if (is_last_block) {
        temp_xored = bits_xor(BLAKE2s_IV[6], flag_to_1);
    }
    std::vector<bool> temp_vector14(temp_xored.begin(), temp_xored.end());
    v[0][14].fill_with_bits(this->pb, temp_vector14);

    // v_15 = f1 XOR IV_7
    temp_xored = BLAKE2s_IV[7];
    std::vector<bool> temp_vector15(temp_xored.begin(), temp_xored.end());
    v[0][15].fill_with_bits(this->pb, temp_vector15);
}

template<typename FieldT> void BLAKE2s_256_comp<FieldT>::setup_mixing_gadgets()
{
    // See: Section 3.2 of https://tools.ietf.org/html/rfc7693
    for (size_t i = 0; i < rounds; i++) {
        // Message word selection permutation for this round
        std::array<uint8_t, 16> s = sigma[i % rounds];

        g_arrays[i].emplace_back(g_primitive<FieldT>(
            this->pb,
            v[i][0],
            v[i][4],
            v[i][8],
            v[i][12],
            block[s[0]],
            block[s[1]],
            v_temp[i][0],
            v_temp[i][4],
            v_temp[i][8],
            v_temp[i][12],
            FMT(this->annotation_prefix, " g_primitive_1_round_%zu", i)));

        g_arrays[i].emplace_back(g_primitive<FieldT>(
            this->pb,
            v[i][1],
            v[i][5],
            v[i][9],
            v[i][13],
            block[s[2]],
            block[s[3]],
            v_temp[i][1],
            v_temp[i][5],
            v_temp[i][9],
            v_temp[i][13],
            FMT(this->annotation_prefix, " g_primitive_2_round_%zu", i)));

        g_arrays[i].emplace_back(g_primitive<FieldT>(
            this->pb,
            v[i][2],
            v[i][6],
            v[i][10],
            v[i][14],
            block[s[4]],
            block[s[5]],
            v_temp[i][2],
            v_temp[i][6],
            v_temp[i][10],
            v_temp[i][14],
            FMT(this->annotation_prefix, " g_primitive_3_round_%zu", i)));

        g_arrays[i].emplace_back(g_primitive<FieldT>(
            this->pb,
            v[i][3],
            v[i][7],
            v[i][11],
            v[i][15],
            block[s[6]],
            block[s[7]],
            v_temp[i][3],
            v_temp[i][7],
            v_temp[i][11],
            v_temp[i][15],
            FMT(this->annotation_prefix, " g_primitive_4_round_%zu", i)));

        g_arrays[i].emplace_back(g_primitive<FieldT>(
            this->pb,
            v_temp[i][0],
            v_temp[i][5],
            v_temp[i][10],
            v_temp[i][15],
            block[s[8]],
            block[s[9]],
            v[i + 1][0],
            v[i + 1][5],
            v[i + 1][10],
            v[i + 1][15],
            FMT(this->annotation_prefix, " g_primitive_5_round_%zu", i)));

        g_arrays[i].emplace_back(g_primitive<FieldT>(
            this->pb,
            v_temp[i][1],
            v_temp[i][6],
            v_temp[i][11],
            v_temp[i][12],
            block[s[10]],
            block[s[11]],
            v[i + 1][1],
            v[i + 1][6],
            v[i + 1][11],
            v[i + 1][12],
            FMT(this->annotation_prefix, " g_primitive_6_round_%zu", i)));

        g_arrays[i].emplace_back(g_primitive<FieldT>(
            this->pb,
            v_temp[i][2],
            v_temp[i][7],
            v_temp[i][8],
            v_temp[i][13],
            block[s[12]],
            block[s[13]],
            v[i + 1][2],
            v[i + 1][7],
            v[i + 1][8],
            v[i + 1][13],
            FMT(this->annotation_prefix, " g_primitive_7_round_%zu", i)));

        g_arrays[i].emplace_back(g_primitive<FieldT>(
            this->pb,
            v_temp[i][3],
            v_temp[i][4],
            v_temp[i][9],
            v_temp[i][14],
            block[s[14]],
            block[s[15]],
            v[i + 1][3],
            v[i + 1][4],
            v[i + 1][9],
            v[i + 1][14],
            FMT(this->annotation_prefix, " g_primitive_8_round_%zu", i)));
    }

    for (size_t i = 0; i < 8; i++) {
        xor_vector.emplace_back(xor_gadget<FieldT>(
            this->pb,
            v[rounds][i],
            v[rounds][8 + i],
            out_temp[i],
            FMT(this->annotation_prefix, " xor_output_temp_%zu", i)));
    }

    for (size_t i = 0; i < 8; i++) {
        xor_vector.emplace_back(xor_gadget<FieldT>(
            this->pb,
            out_temp[i],
            h_array[i],
            output_bytes[i],
            FMT(this->annotation_prefix, " xor_output_%zu", i)));
    }
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_BLAKE2S_COMP_SETUP_TCC__
