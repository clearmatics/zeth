// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/bits.hpp"

namespace libzeth
{

std::vector<bool> bits32_to_vector(const bits32 &arr)
{
    return array_to_vector<32>(arr);
}

bits64 bits64_from_vector(const std::vector<bool> &vect)
{
    return vector_to_array<64>(vect);
}

bits64 bits64_from_hex(const std::string &str)
{
    if (str.length() != 16) {
        throw std::length_error(
            "Invalid string length for the given hex digest (should be "
            "16)");
    }

    return bits64_from_vector(bit_vector_from_hex(str));
}

std::vector<bool> bits64_to_vector(const bits64 &arr)
{
    return array_to_vector<64>(arr);
}

bits256 bits256_from_vector(const std::vector<bool> &vect)
{
    return vector_to_array<256>(vect);
}

bits256 bits256_from_hex(const std::string &str)
{
    if (str.length() != 64) {
        throw std::length_error(
            "Invalid string length for the given hex digest (should be "
            "64)");
    }

    return bits256_from_vector(bit_vector_from_hex(str));
}

std::vector<bool> bits256_to_vector(const bits256 &arr)
{
    return array_to_vector<256>(arr);
}

bits384 bits384_from_vector(const std::vector<bool> &vect)
{
    return vector_to_array<384>(vect);
}

bits384 bits384_from_hex(const std::string &str)
{
    if (str.length() != 96) {
        throw std::length_error(
            "Invalid string length for the given hex digest (should be "
            "96)");
    }

    return bits384_from_vector(bit_vector_from_hex(str));
}

std::vector<bool> bits384_to_vector(const bits384 &arr)
{
    return array_to_vector<384>(arr);
}

std::vector<bool> bit_vector_from_hex(const std::string &hex_str)
{
    std::vector<bool> result;
    std::vector<bool> tmp;
    // Each hex character is encoded on 4 bits
    std::vector<bool> zero_vector(hex_str.length() * 4, 0);

    static const std::vector<bool> vect0 = {0, 0, 0, 0};
    static const std::vector<bool> vect1 = {0, 0, 0, 1};
    static const std::vector<bool> vect2 = {0, 0, 1, 0};
    static const std::vector<bool> vect3 = {0, 0, 1, 1};
    static const std::vector<bool> vect4 = {0, 1, 0, 0};
    static const std::vector<bool> vect5 = {0, 1, 0, 1};
    static const std::vector<bool> vect6 = {0, 1, 1, 0};
    static const std::vector<bool> vect7 = {0, 1, 1, 1};
    static const std::vector<bool> vect8 = {1, 0, 0, 0};
    static const std::vector<bool> vect9 = {1, 0, 0, 1};
    static const std::vector<bool> vectA = {1, 0, 1, 0};
    static const std::vector<bool> vectB = {1, 0, 1, 1};
    static const std::vector<bool> vectC = {1, 1, 0, 0};
    static const std::vector<bool> vectD = {1, 1, 0, 1};
    static const std::vector<bool> vectE = {1, 1, 1, 0};
    static const std::vector<bool> vectF = {1, 1, 1, 1};

    for (std::string::const_iterator it = hex_str.begin(); it != hex_str.end();
         ++it) {
        switch (*it) {
        case '0':
            tmp = vect0;
            break;
        case '1':
            tmp = vect1;
            break;
        case '2':
            tmp = vect2;
            break;
        case '3':
            tmp = vect3;
            break;
        case '4':
            tmp = vect4;
            break;
        case '5':
            tmp = vect5;
            break;
        case '6':
            tmp = vect6;
            break;
        case '7':
            tmp = vect7;
            break;
        case '8':
            tmp = vect8;
            break;
        case '9':
            tmp = vect9;
            break;
        case 'A':
            tmp = vectA;
            break;
        case 'a':
            tmp = vectA;
            break;
        case 'B':
            tmp = vectB;
            break;
        case 'b':
            tmp = vectB;
            break;
        case 'C':
            tmp = vectC;
            break;
        case 'c':
            tmp = vectC;
            break;
        case 'D':
            tmp = vectD;
            break;
        case 'd':
            tmp = vectD;
            break;
        case 'E':
            tmp = vectE;
            break;
        case 'e':
            tmp = vectE;
            break;
        case 'F':
            tmp = vectF;
            break;
        case 'f':
            tmp = vectF;
            break;
        default:
            throw std::invalid_argument("Invalid hexadecimnal character");
        }
        result.insert(std::end(result), std::begin(tmp), std::end(tmp));
    }

    return result;
}

std::vector<bool> bit_vector_from_size_t_le(size_t x)
{
    std::vector<bool> ret;
    while (x) {
        if (x & 1) {
            ret.push_back(1);
        } else {
            ret.push_back(0);
        }
        x >>= 1;
    }

    return ret;
}

std::vector<bool> bit_vector_from_size_t_be(size_t n)
{
    std::vector<bool> res;

    if (n / 2 != 0) {
        std::vector<bool> temp = bit_vector_from_size_t_be(n / 2);
        res.insert(res.end(), temp.begin(), temp.end());
    }

    if (n % 2 == 1) {
        res.push_back(1);
    } else {
        res.push_back(0);
    }

    return res;
}

} // namespace libzeth
