#ifndef __ZETH_BITS_TCC__
#define __ZETH_BITS_TCC__

namespace libzeth
{

// Dump a vector into an array
template<size_t Size>
std::array<bool, Size> dump_vector_in_array(std::vector<bool> vect)
{
    std::array<bool, Size> array;
    if (vect.size() != Size) {
        throw std::length_error(
            "Invalid bit length for the given boolean vector (should be equal "
            "to the size of the vector)");
    }

    std::copy(vect.begin(), vect.end(), array.begin());
    return array;
};

// Dump an array into a vector
template<size_t Size>
std::vector<bool> dump_array_in_vector(std::array<bool, Size> arr)
{
    std::vector<bool> vect(Size);
    std::copy(arr.begin(), arr.end(), vect.begin());
    return vect;
}

// Sum 2 binary strings
template<size_t BitLen>
std::array<bool, BitLen> binaryAddition(
    std::array<bool, BitLen> A, std::array<bool, BitLen> B)
{
    std::array<bool, BitLen> sum;
    sum.fill(0);

    bool carry = 0;
    for (int i = BitLen - 1; i >= 0; i--) {
        sum[i] = ((A[i] ^ B[i]) ^ carry); // c is carry
        carry = ((A[i] & B[i]) | (A[i] & carry)) | (B[i] & carry);
    }

    // If the last carry is 1, then we have an overflow
    if (carry) {
        throw std::overflow_error("Overflow: The sum of the binary addition "
                                  "cannot be encoded on <BitLen> bits");
    }

    return sum;
}

// Sum 2 binary strings, discard last carry
template<size_t BitLen>
std::array<bool, BitLen> binaryAdditionNoCarry(
    std::array<bool, BitLen> A, std::array<bool, BitLen> B)
{
    std::array<bool, BitLen> sum;
    sum.fill(0);

    bool carry = 0;
    for (int i = BitLen - 1; i >= 0; i--) {
        sum[i] = ((A[i] ^ B[i]) ^ carry); // c is carry
        carry = ((A[i] & B[i]) | (A[i] & carry)) | (B[i] & carry);
    }

    return sum;
}

// XOR 2 binary strings
template<size_t BitLen>
std::array<bool, BitLen> binaryXOR(
    std::array<bool, BitLen> A, std::array<bool, BitLen> B)
{
    std::array<bool, BitLen> xor_array;
    xor_array.fill(0);

    for (int i = BitLen - 1; i >= 0; i--) {
        xor_array[i] = A[i] != B[i]; // c is carry
    }

    return xor_array;
}

} // namespace libzeth

#endif // __ZETH_BITS_TCC__