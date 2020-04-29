// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/utils.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace libzeth
{

static uint8_t char_to_nibble(const char c)
{
    const char cc = std::tolower(c);
    assert((cc >= '0' && cc <= '9') || (cc >= 'a' && cc <= 'z'));
    if (cc <= '9') {
        return cc - '0';
    }

    return cc - 'a' + 10;
}

static uint8_t chars_to_byte(const char *cs)
{
    const uint8_t *data = (const uint8_t *)cs;
    return (char_to_nibble(data[0]) << 4) | char_to_nibble(data[1]);
}

static char nibble_hex(const uint8_t nibble)
{
    assert((nibble & 0xf0) == 0);
    if (nibble > 9) {
        return 'a' + nibble - 10;
    }

    return '0' + nibble;
}

std::string hex_to_bytes(const std::string &s)
{
    assert(s.size() % 2 == 0);
    const char *cs = s.c_str();
    std::string out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        out.push_back((char)chars_to_byte(&cs[i]));
    }

    return out;
}

std::string bytes_to_hex(const void *s, const size_t size)
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

std::string bytes_to_hex(const std::string &s)
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

int hex_to_bytes(char *source_str, uint8_t *dest_buffer)
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
