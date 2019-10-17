#ifndef __ZETH_UTIL_TCC__
#define __ZETH_UTIL_TCC__

#include "util.hpp"

namespace libzeth
{

// Takes a binary string and swaps the bit endianness
template<typename T> T swap_bit_endianness(T v)
{
    size_t len = v.size();
    if (len == 0) {
        throw std::length_error(
            "Invalid bit length for the given boolean vector (should be > 0)");
    }

    for (size_t i = 0; i < len / 2; i++) {
        std::swap(v[i], v[(len - 1) - i]);
    }

    return v;
}

// string_to_field(std::string input) converts a string ob bytes of size <=32 to
// a FieldT element.
template<typename FieldT> FieldT string_to_field(std::string input)
{

    int input_len = input.length();

    // Sanity checks
    // length
    if (input_len == 0 || input.length() > 64) {
        throw std::length_error(
            "Invalid byte string length for the given field string");
    }

    // Copy the string into a char array
    char char_array[input.length() + 1];
    strcpy(char_array, input.c_str());

    // Construct gmp integer from the string
    mpz_t n;
    mpz_init(n);

    int flag = mpz_set_str(n, char_array, 16);
    if (flag != 0) {
        throw std::runtime_error(std::string("Invalid hex string"));
    };

    // Construct libff::bigint from gmp integer
    libff::bigint<4> n_big_int = libff::bigint<4>(n);

    // Construct field element from a bigint
    FieldT element = FieldT(n_big_int);
    return element;
}

template<typename V> bool container_is_well_formed(const V &values)
{
    for (const auto &v : values) {
        if (!v.is_well_formed()) {
            return false;
        }
    }

    return true;
}

template<typename T> void check_well_formed(const T &v, const char *name)
{
    if (!v.is_well_formed()) {
        throw std::invalid_argument(std::string(name) + " not well-formed");
    }
}

template<typename T> void check_well_formed_(const T &v, const char *name)
{
    if (!is_well_formed(v)) {
        throw std::invalid_argument(std::string(name) + " not well-formed");
    }
}

} // namespace libzeth

#endif // __ZETH_UTIL_TCC__
