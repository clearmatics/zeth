// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/util.hpp"
#include "libzeth/zeth.h"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace libzeth
{

std::vector<bool> hexadecimal_str_to_binary_vector(std::string hex_str)
{
    std::vector<bool> result;
    std::vector<bool> tmp;
    // Each hex character is encoded on 4 bits
    std::vector<bool> zero_vector(hex_str.length() * 4, 0);

    const std::vector<bool> vect0 = {0, 0, 0, 0};
    const std::vector<bool> vect1 = {0, 0, 0, 1};
    const std::vector<bool> vect2 = {0, 0, 1, 0};
    const std::vector<bool> vect3 = {0, 0, 1, 1};
    const std::vector<bool> vect4 = {0, 1, 0, 0};
    const std::vector<bool> vect5 = {0, 1, 0, 1};
    const std::vector<bool> vect6 = {0, 1, 1, 0};
    const std::vector<bool> vect7 = {0, 1, 1, 1};
    const std::vector<bool> vect8 = {1, 0, 0, 0};
    const std::vector<bool> vect9 = {1, 0, 0, 1};
    const std::vector<bool> vectA = {1, 0, 1, 0};
    const std::vector<bool> vectB = {1, 0, 1, 1};
    const std::vector<bool> vectC = {1, 1, 0, 0};
    const std::vector<bool> vectD = {1, 1, 0, 1};
    const std::vector<bool> vectE = {1, 1, 1, 0};
    const std::vector<bool> vectF = {1, 1, 1, 1};

    for (std::string::iterator it = hex_str.begin(); it != hex_str.end();
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

std::vector<bool> hexadecimal_digest_to_binary_vector(std::string hex_str)
{
    return hexadecimal_str_to_binary_vector(hex_str);
}

/// Returns the binary representation of the given
/// unsigned integer of type `size_t`.
std::vector<bool> convert_uint_to_binary(size_t x)
{
    std::vector<bool> ret;
    while (x) {
        if (x & 1)
            ret.push_back(1);
        else
            ret.push_back(0);
        x >>= 1;
    }
    return ret;
}

static uint8_t hex_nibble(const char c)
{
    const char cc = std::tolower(c);
    assert((cc >= '0' && cc <= '9') || (cc >= 'a' && cc <= 'z'));
    if (cc <= '9') {
        return cc - '0';
    }

    return cc - 'a' + 10;
}

static uint8_t hex_byte(const char *cs)
{
    const uint8_t *data = (const uint8_t *)cs;
    return (hex_nibble(data[0]) << 4) | hex_nibble(data[1]);
}

static char nibble_hex(const uint8_t nibble)
{
    assert((nibble & 0xf0) == 0);
    if (nibble > 9) {
        return 'a' + nibble - 10;
    }

    return '0' + nibble;
}

std::string hexadecimal_str_to_binary_str(const std::string &s)
{
    assert(s.size() % 2 == 0);
    const char *cs = s.c_str();
    std::string out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        out.push_back((char)hex_byte(&cs[i]));
    }

    return out;
}

std::string binary_str_to_hexadecimal_str(const void *s, const size_t size)
{
    std::string out;
    out.reserve(size * 2);

    const uint8_t *in = (const uint8_t *)s;
    for (size_t i = 0; i < size; ++i) {
        const uint8_t byte = in[i];
        out.push_back(nibble_hex(byte >> 4));
        out.push_back(nibble_hex(byte & 0x0f));
    }

    return out;
}

std::string binary_str_to_hexadecimal_str(const std::string &s)
{
    std::string out;
    out.reserve(s.size() * 2);

    const uint8_t *in = (const uint8_t *)s.c_str();
    for (size_t i = 0; i < s.size(); ++i) {
        const uint8_t byte = in[i];
        out.push_back(nibble_hex(byte >> 4));
        out.push_back(nibble_hex(byte & 0x0f));
    }

    return out;
}

int hexadecimal_str_to_byte_array(char *source_str, uint8_t *dest_buffer)
{
    char *line = source_str;
    char *data = line;
    int offset;
    int read_byte;
    int data_len = 0;

    while (sscanf(data, "%02x%n", &read_byte, &offset) == 1) {
        dest_buffer[data_len++] = read_byte;
        data += offset;
    }
    return data_len;
}

void erase_substring(std::string &string, const std::string &substring)
{
    size_t position = string.find(substring);

    if (position != std::string::npos) {
        string.erase(position, substring.length());
    }
}

} // namespace libzeth
