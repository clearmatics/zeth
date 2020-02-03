// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_BLAKE2S_COMP_SETUP_TCC__
#define __ZETH_CIRCUITS_BLAKE2S_COMP_SETUP_TCC__

namespace libzeth
{

template<typename FieldT> void BLAKE2s_256_comp<FieldT>::setup_constants()
{
    // See: Appendix A.2 of https://blake2.net/blake2.pdf for the specification
    // of the IV used in BLAKE2s
    IV[0] = {
        0, 1, 1, 0, 1, 0, 1, 0, // 6A
        0, 0, 0, 0, 1, 0, 0, 1, // 09
        1, 1, 1, 0, 0, 1, 1, 0, // E6
        0, 1, 1, 0, 0, 1, 1, 1  // 67
    };

    IV[1] = {
        1, 0, 1, 1, 1, 0, 1, 1, // BB
        0, 1, 1, 0, 0, 1, 1, 1, // 67
        1, 0, 1, 0, 1, 1, 1, 0, // AE
        1, 0, 0, 0, 0, 1, 0, 1  // 85
    };

    IV[2] = {
        0, 0, 1, 1, 1, 1, 0, 0, // 3C
        0, 1, 1, 0, 1, 1, 1, 0, // 6E
        1, 1, 1, 1, 0, 0, 1, 1, // F3
        0, 1, 1, 1, 0, 0, 1, 0  // 72
    };

    IV[3] = {
        1, 0, 1, 0, 0, 1, 0, 1, // A5
        0, 1, 0, 0, 1, 1, 1, 1, // 4F
        1, 1, 1, 1, 0, 1, 0, 1, // F5
        0, 0, 1, 1, 1, 0, 1, 0  // 3A
    };

    IV[4] = {
        0, 1, 0, 1, 0, 0, 0, 1, // 51
        0, 0, 0, 0, 1, 1, 1, 0, // 0E
        0, 1, 0, 1, 0, 0, 1, 0, // 52
        0, 1, 1, 1, 1, 1, 1, 1  // 7F
    };

    IV[5] = {
        1, 0, 0, 1, 1, 0, 1, 1, // 9B
        0, 0, 0, 0, 0, 1, 0, 1, // 05
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        1, 0, 0, 0, 1, 1, 0, 0  // 8C

    };

    IV[6] = {
        0, 0, 0, 1, 1, 1, 1, 1, // 1F
        1, 0, 0, 0, 0, 0, 1, 1, // 83
        1, 1, 0, 1, 1, 0, 0, 1, // D9
        1, 0, 1, 0, 1, 0, 1, 1  // AB
    };

    IV[7] = {
        0, 1, 0, 1, 1, 0, 1, 1, // 5B
        1, 1, 1, 0, 0, 0, 0, 0, // E0
        1, 1, 0, 0, 1, 1, 0, 1, // CD
        0, 0, 0, 1, 1, 0, 0, 1  // 19
    };

    // See: Appendix A.1 of https://blake2.net/blake2.pdf for the specification
    // of the permutations used in BLAKE2s
    sigma[0] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    sigma[1] = {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3};
    sigma[2] = {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4};
    sigma[3] = {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8};
    sigma[4] = {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13};
    sigma[5] = {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9};
    sigma[6] = {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11};
    sigma[7] = {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10};
    sigma[8] = {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5};
    sigma[9] = {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0};
}

template<typename FieldT> void BLAKE2s_256_comp<FieldT>::setup_h()
{
    // Parameter block, size set to 32 bytes, fanout and depth set to serial
    // mode
    std::array<std::array<bool, BLAKE2s_word_size>, 8> parameter_block;
    // See: Section 2.8 https://blake2.net/blake2.pdf Table 2
    // Digest byte length, Key byte length, Fanout, Depth
    parameter_block[0] = {
        0, 0, 1, 0, 0, 0, 0, 0, // 0x20 (32 bytes)
        0, 0, 0, 0, 0, 0, 0, 0, // 0x00 (key length)
        0, 0, 0, 0, 0, 0, 0, 1, // 0x01 (fanout 1)
        0, 0, 0, 0, 0, 0, 0, 1  // 0x01 (depth 1)
    };

    // Leaf length
    parameter_block[1] = {
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0  // 00
    };

    // Node offset
    parameter_block[2] = {
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0  // 00
    };

    // Node offset (cont.), Node depth, Inner length
    parameter_block[3] = {
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00 (node depth)
        0, 0, 0, 0, 0, 0, 0, 0  // 00 (inner length)
    };

    // Salt
    parameter_block[4] = {
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0  // 00
    };
    parameter_block[5] = {
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0  // 00
    };

    // Personalization
    parameter_block[6] = {
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0  // 00
    };
    parameter_block[7] = {
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0  // 00
    };

    // See: Appendix A.1 of https://blake2.net/blake2.pdf
    for (size_t i = 0; i < 8; i++) {
        std::array<bool, BLAKE2s_word_size> pb_swapped =
            swap_byte_endianness(parameter_block[i]);
        std::array<bool, BLAKE2s_word_size> IVi = IV[i];
        h[i] = binary_xor(pb_swapped, IVi);
    }
}

template<typename FieldT>
void BLAKE2s_256_comp<FieldT>::setup_counter(size_t len_input_block)
{
    // len_input_block represents the BYTE length of the input block
    // we can hash at most 2^64 - 1 bytes with blake2s
    std::vector<bool> length_bits = convert_to_binary(len_input_block);
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
template<typename FieldT> void BLAKE2s_256_comp<FieldT>::setup_v()
{
    // [v_0, ..., v_7] = [h_0, ..., h_7]
    for (size_t i = 0; i < 8; i++) {
        std::vector<bool> temp_vector(h[i].begin(), h[i].end());
        v[0][i].fill_with_bits(this->pb, temp_vector);
    }

    // [v_8, v_9, v_10, v_11] = [IV_0, IV_1, IV_2, IV_3]
    for (size_t i = 8; i < 12; i++) {
        std::vector<bool> temp_vector(IV[i - 8].begin(), IV[i - 8].end());
        v[0][i].fill_with_bits(this->pb, temp_vector);
    }

    // v_12 = t0 XOR IV_4
    std::array<bool, 32> temp_xored = binary_xor(IV[4], t[0]);
    std::vector<bool> temp_vector12(temp_xored.begin(), temp_xored.end());
    v[0][12].fill_with_bits(this->pb, temp_vector12);

    // v_13 = t1 XOR IV_5
    temp_xored = binary_xor(IV[5], t[1]);
    std::vector<bool> temp_vector13(temp_xored.begin(), temp_xored.end());
    v[0][13].fill_with_bits(this->pb, temp_vector13);

    // v_14 = f0 XOR IV_6
    temp_xored = binary_xor(IV[6], f0);
    std::vector<bool> temp_vector14(temp_xored.begin(), temp_xored.end());
    v[0][14].fill_with_bits(this->pb, temp_vector14);

    // v_15 = f1 XOR IV_7
    temp_xored = binary_xor(IV[7], f1);
    std::vector<bool> temp_vector15(temp_xored.begin(), temp_xored.end());
    v[0][15].fill_with_bits(this->pb, temp_vector15);
}

template<typename FieldT> void BLAKE2s_256_comp<FieldT>::setup_mixing_gadgets()
{
    // See: Section 3.2 of https://tools.ietf.org/html/rfc7693
    for (size_t i = 0; i < rounds; i++) {
        // Message word selection permutation for this round
        std::array<uint, 16> s = sigma[i % rounds];

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
        std::vector<FieldT> temp_field_vector(h[i].begin(), h[i].end());
        xor_vector.emplace_back(xor_constant_gadget<FieldT>(
            this->pb,
            v[rounds][i],
            v[rounds][8 + i],
            temp_field_vector,
            output_bytes[i],
            FMT(this->annotation_prefix, " xor_output_%zu", i)));
    }
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_BLAKE2S_COMP_SETUP_TCC__
