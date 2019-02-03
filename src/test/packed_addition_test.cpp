#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Header to use the sha256_ethereum gadget
#include "sha256_ethereum.hpp"

#include "util.hpp"

// Access the defined constants
#include "zeth.h"

// Include the type we need
#include "bits256.tcc"
#include "joinsplit.hpp"
#include "note.hpp"

// Gadgets to test
#include "circuits-util.tcc"

using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT; // Should be alt_bn128 in the CMakeLists.txt
typedef sha256_ethereum<FieldT> HashT; // We use our hash function to do the tests

namespace {

void dump_bit_vector(std::ostream &out, const libff::bit_vector &v)
{
    out << "{";
    for (size_t i = 0; i < v.size() - 1; ++i)
    {
        out << v[i] << ", ";
    }
    out << v[v.size() - 1] << "}\n";
}

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

TEST(TestPackedAddition, TestPackedAddition) {
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb);
    pb.val(ZERO) = FieldT::zero();

    // === Set the constraints
    libsnark::pb_variable_array<FieldT> value_left;
    value_left.allocate(pb, 64);
    libsnark::pb_variable_array<FieldT> value_left_2;
    value_left_2.allocate(pb, 64);
    
    libsnark::pb_variable_array<FieldT> value_right;
    value_right.allocate(pb, 64);

    libsnark::linear_combination<FieldT> left_side = packed_addition(value_left) + packed_addition(value_left_2);
    libsnark::linear_combination<FieldT> right_side = packed_addition(value_right);

    // Constraint to ensure that both sides are equal
    pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
        1,
        left_side,
        right_side
    ));

    // === Witness
    char* value_left_str = "000000000000000A";
    char* value_left_str_2 = "000000000000000A";
    bits64 value_left_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_left_str));
    value_left.fill_with_bits(pb, libff::bit_vector(get_vector_from_bits64(value_left_bits64)));

    bits64 value_left_2_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_left_str_2));
    value_left_2.fill_with_bits(pb, libff::bit_vector(get_vector_from_bits64(value_left_2_bits64)));

    // 0A + 0A = 14 in hexa
    char* value_right_str = "0000000000000014";
    bits64 value_right_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_right_str));
    value_right.fill_with_bits(pb, libff::bit_vector(get_vector_from_bits64(value_right_bits64)));

    bool witness_bool = pb.is_satisfied();
    std::cout << "************* SAT result: " << witness_bool <<  " ******************" << std::endl;
};

} // namespace

int main(int argc, char **argv) {
    ppT::init_public_params(); // /!\ WARNING: Do once for all tests. Do not forget to do this !!!!
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}