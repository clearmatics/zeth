#ifndef __ZETH_CIRCUITS_UTILS_TCC__
#define __ZETH_CIRCUITS_UTILS_TCC__

#include <vector>
#include <libsnark/gadgetlib1/pb_variable.hpp>

namespace libzeth {

// Converts a given number encoded on bitlen bits into a
// binary string of lentgh bitlen.
// The encoding is Little Endian.
template<typename T>
std::vector<bool> convert_to_binary_LE(T x, int bitlen) {
    std::vector<bool> ret;
    for(int i = 0; i < bitlen; i++){
        if (x&1)
            ret.push_back(1);
        else
            ret.push_back(0);
        x>>=1;
    }
    return ret;
};

/*
 * This function reverses the endianness at the byte level
 * 
 *  Example input/output:
 *
 *  Before swap (in):  After Swap (out):
 *    0011 0111         0000 0000
 *    1000 0010         0000 0000
 *    1101 1010         1001 0000
 *    1100 1110         1001 1101
 *    1001 1101         1100 1110
 *    1001 0000         1101 1010
 *    0000 0000         1000 0010
 *    0000 0000         0011 0111
 *
**/
template<typename T>
T swap_endianness_u64(T v) {
    if (v.size() != 64) {
        throw std::length_error("invalid bit length for 64-bit unsigned integer");
    }

    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 8; j++) {
            std::swap(v[i*8 + j], v[((7-i)*8)+j]);
        }
    }

    return v;
};

/*
 * This function reverses the endianness at the byte level
 * and then calls the pb_packing_sum on the binary reverse of the swapped bytes
 * (ie: change the BIT endianness of the obtained swapped byte string)
 * 
 *  Example input/output:
 *
 *  Before swap (in):  After Swap (out):
 *    0011 0111         0000 0000
 *    1000 0010         0000 0000
 *    1101 1010         1001 0000
 *    1100 1110         1001 1101
 *    1001 1101         1100 1110
 *    1001 0000         1101 1010
 *    0000 0000         1000 0010
 *    0000 0000         0011 0111
 * 
 * In hexadecimal:
 * - Input = 0x3782DACE9D900000
 * - Output = 0x000009B9735B41EC
 * 
 * Then `input_swapped.rbegin(), input_swapped.rend()` basically reads the binary string
 * "0000 0000 0000 0000 1001 0000 1001 1101 1100 1110 1101 1010 1000 0010 0011 0111"
 *                                                                                ^
 *                                              (reading direction) <---  rbegin _|
 *                                                                                  
 * backwards, in order to get the binary string:
 * "1110 1100 0100 0001 0101 1011 0111 0011 1011 1001 0000 1001 0000 0000 0000 0000"
 * 
 * Which gives the following hexadecimal string:
 * - Result: 0xEC415B73B9090000
**/

// Careful when we carry out a sum on a byte string that has been swapped, as swapping the bytes affects
// the way the carry is is propagated
// Example: 
// (1) 0x3782 + 0x26A1 = 0x5E23 (Here 8 + A = 2 + Carry that propagates to the next byte to give a 7 + 6 + 1(the carry) = E)
// (2) 0x2A13 + 0x3410 = 0x5E23
// Thus we have (1) = (2) here
//
// Now we swap the bytes:
// (1') 0x8237 + 0xA126 = 0x235C (Here the carry coming from 8 + A engenders an overflow, and is not applied to 7 + 6 which is sum gives C as the last byte)
// (2') 0x132A + 0x1034 = 0x235D
// After the byte swap we have (1') =/= (2')
// Thus swapping the bytes affects the way the carries are propagated. Thus, equalities are not necessarily preserved after swapping.
/*
template<typename FieldT>
libsnark::linear_combination<FieldT> packed_addition(libsnark::pb_variable_array<FieldT> input) {
    auto input_swapped = swap_endianness_u64(input);

    return libsnark::pb_packing_sum<FieldT>(libsnark::pb_variable_array<FieldT>(
        input_swapped.rbegin(), input_swapped.rend()
    ));
};
*/

template<typename FieldT>
libsnark::linear_combination<FieldT> packed_addition(libsnark::pb_variable_array<FieldT> inputs) {
    // We use `inputs.rbegin(), inputs.rend()` otherwise the resulting linear combination is
    // built by interpreting our bit string as little endian. Thus here, we make sure our binary
    // string is interpreted correctly.
    return libsnark::pb_packing_sum<FieldT>(libsnark::pb_variable_array<FieldT>(
        inputs.rbegin(), inputs.rend()
    ));
};

/*
Notes about the `packed_addition`.

The packed addition takes a `pb_variable_array` as input and calls the `pb_packing_sum` function to return a 
`linear_combination`.
We know that a linear combination is in the form: 
`Sum_i coeff_i * var_i`, where the coeffs are field elements and var_i denotes the ith variable in the
list of variables of the R1CS.

Each term of the linear combination is a linear term and has the form: `coeff_i * var_i`.
Bascially the packed addition will create a linear combination in the form:
    A*X, where A and X are vectors of size N (N denotes the number of variables) in the `pb_variable_array`

The vector A represents the vector of coefficients, and the vector X represents the vector of variables.
The coefficients are the powers of 2 from 0 to the size of the `pb_variable_array` - 1, and the variables
are boolean/bit variables that correspond to the bit encoding of the number.

Example:
1) pb_variable_array<FieldT> var
2) var.allocate(4) // 4 bits to encode the integer represented by `var`
3) libsnark::linear_combination<FieldT> lin_comb = packed_addition(var);

At that point lin_comb is in the form:
A = |1| (2^0)  and X = |x_0|
    |2| (2^1)          |x_1|
    |4| (2^2)          |x_2|
    |8| (2^3)          |x_3|

4) Now we assign a value to `var`, var.fill_with_bits({1,0,0,1})
5) The lin comb becomes:
A = |1| (2^0)  and X = |1|
    |2| (2^1)          |0|
    |4| (2^2)          |0|
    |8| (2^3)          |1|
*/


// TODO: Uncomment the function below
//
// From_bits() takes a vector of boolean values, and convert this vector of boolean values into a vector of
// identities in the field FieldT, where bool(0) <-> ZERO (Additive identity in FieldT), and where
// bool(1) <-> ONE (Multiplicative identity in FieldT)

/*
template<typename FieldT>
libsnark::pb_variable_array<FieldT> from_bits(std::vector<bool> bits, libsnark::pb_variable<FieldT>& ZERO)
{
    libsnark::pb_variable_array<FieldT> acc;
    for (size_t i = 0; i < bits.size(); i++) {
        bool bit = bits[i];
        acc.emplace_back(bit ? ONE : ZERO);
    }

    return acc;
}
*/

} // libzeth

#endif // __ZETH_CIRCUITS_UTILS_TCC__