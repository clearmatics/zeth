#include "bits.hpp"

namespace libzeth
{

bits384 get_bits384_from_vector(std::vector<bool> vect)
{
    return dump_vector_in_array<384>(vect);
}

bits256 get_bits256_from_vector(std::vector<bool> vect)
{
    return dump_vector_in_array<256>(vect);
}

bits64 get_bits64_from_vector(std::vector<bool> vect)
{
    return dump_vector_in_array<64>(vect);
}

bits32 get_bits32_from_vector(std::vector<bool> vect)
{
    return dump_vector_in_array<32>(vect);
}

bits_addr get_bits_addr_from_vector(std::vector<bool> vect)
{
    return dump_vector_in_array<ZETH_MERKLE_TREE_DEPTH>(vect);
}

std::vector<bool> get_vector_from_bits384(bits384 arr)
{
    return dump_array_in_vector<384>(arr);
}

std::vector<bool> get_vector_from_bits256(bits256 arr)
{
    return dump_array_in_vector<256>(arr);
}

std::vector<bool> get_vector_from_bits64(bits64 arr)
{
    return dump_array_in_vector<64>(arr);
}

std::vector<bool> get_vector_from_bits32(bits32 arr)
{
    return dump_array_in_vector<32>(arr);
}

std::vector<bool> get_vector_from_bits_addr(bits_addr arr)
{
    return dump_array_in_vector<ZETH_MERKLE_TREE_DEPTH>(arr);
}

bits64 sum_bits64(bits64 a, bits64 b)
{
    std::array<bool, 64> sum;

    try {
        sum = binary_addition(a, b);
    } catch (const std::overflow_error &e) {
        // We return 0 encoded in binary if we overflow
        sum.fill(0);
    }

    return sum;
}

} // namespace libzeth