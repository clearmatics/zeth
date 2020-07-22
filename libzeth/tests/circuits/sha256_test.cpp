// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "core/bits.hpp"
#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/circuits/sha256/sha256_ethereum.hpp"
#include "zeth_config.h"

#include <gtest/gtest.h>
#include <libsnark/common/data_structures/merkle_tree.hpp>

using namespace libsnark;
using pp = libzeth::defaults::pp;
using Field = libzeth::defaults::Field;

// We use our hash function to do the tests
using HashT = libzeth::sha256_ethereum<Field>;

// Note on the instantiation of the Field template type
//
// We use the alt_bn128_pp public params, with a field instantiated with
// libff::Fr<pp> which corresponds (according to
// libff/algebra/curves/public_params.hpp) to the typedef 'typedef alt_bn128_Fr
// Fp_type;' (see: libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp)
// 'alt_bn128_Fr' being itself defined in
// 'libff/algebra/curves/alt_bn128/alt_bn128_init.hpp' as 'typedef
// Fp_model<alt_bn128_r_limbs, alt_bn128_modulus_r> alt_bn128_Fr;'
//
// The Fp_model class is defined in 'libff/algebra/fields/fp.hpp' and implements
// arithmetic in the finite field F[p], for prime p of fixed length. (p being
// passed as a template) like:
// ```
// template<mp_size_t n, const bigint<n>& modulus>
// class Fp_model {
// ```
//
// In our case, the modulus is 'alt_bn128_modulus_r' is initialized to the
// value: ` alt_bn128_modulus_r =
// bigint_r("21888242871839275222246405745257275088548364400416034343698204186575808495617");`
// in the 'libff/algebra/curves/alt_bn128/alt_bn128_init.hpp' file

namespace
{

void dump_bit_vector(std::ostream &out, const libff::bit_vector &v)
{
    out << "{";
    for (size_t i = 0; i < v.size() - 1; ++i) {
        out << v[i] << ", ";
    }
    out << v[v.size() - 1] << "}\n";
}

TEST(TestSHA256, TestHash)
{
    libsnark::protoboard<Field> pb;
    libsnark::pb_variable<Field> ZERO;
    ZERO.allocate(pb, "ZERO");
    pb.val(ZERO) = Field::zero();

    // hex: 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<Field> left =
        libzeth::variable_array_from_bit_vector(
            {
                0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, //
            },
            ZERO);

    // hex: 0x43C000000000003FC00000000000003FC00000000000003FC00000000000003F
    libsnark::pb_variable_array<Field> right =
        libzeth::variable_array_from_bit_vector(
            {
                0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, //
                1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, //
                1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, //
                1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, //
            },
            ZERO);

    libsnark::digest_variable<Field> result(
        pb, HashT::get_digest_len(), "result");
    libsnark::block_variable<Field> input_block(
        pb, {left, right}, "Block_variable");
    libzeth::sha256_ethereum<Field> hasher(pb, ZERO, input_block, result);

    // result should equal:
    // 0xa4cc8f23d1dfeab58d7af00b3422f22dd60b9c608af5f30744073653236562c3 Since
    // result = sha256(left || right), where:
    // - left =
    // 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    // - right =
    // 0x43C000000000003FC00000000000003FC00000000000003FC00000000000003F
    //
    // Note: This test vector has been generated by using the solidity sha256
    // function (we want to make sure that we generate the same digests both
    // on-chain and off-chain) Solidity version v0.5.0
    std::string test_vector_res_str =
        "a4cc8f23d1dfeab58d7af00b3422f22dd60b9c608af5f30744073653236562c3";
    libsnark::pb_variable_array<Field> expected =
        libzeth::variable_array_from_bit_vector(
            libzeth::bit_vector_from_hex(test_vector_res_str), ZERO);

    hasher.generate_r1cs_constraints(true);
    hasher.generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);

    std::ostream &stream = std::cout;
    std::cout << " -- Result digest -- " << std::endl;
    dump_bit_vector(stream, result.get_digest());
    std::cout << " -- Expected digest -- " << std::endl;
    dump_bit_vector(stream, expected.get_bits(pb));

    ASSERT_EQ(result.get_digest(), expected.get_bits(pb));
};

TEST(TestSHA256, TestHashWithZeroLeg)
{
    libsnark::protoboard<Field> pb;
    libsnark::pb_variable<Field> ZERO;
    ZERO.allocate(pb, "ZERO");
    pb.val(ZERO) = Field::zero();

    libsnark::pb_variable_array<Field> left;
    libsnark::pb_variable_array<Field> right;
    left.allocate(pb, 256, " left_part_block");
    right.allocate(pb, 256, " right_part_block");

    std::string left_str =
        "806e5c213a2f3d436273e924eb6311ac2db6c33624b28165b79c779e00fa2752";
    std::string right_str =
        "0000000000000000000000000000000000000000000000000000000000000000";
    std::string expected_str =
        "a631eca6f9fc96e9b0135804aceb5e97df404c3877d14e7f5ea67b4c120cec44";

    libff::bit_vector left_bits =
        libff::bit_vector(libzeth::bit_vector_from_hex(left_str));
    libff::bit_vector right_bits =
        libff::bit_vector(libzeth::bit_vector_from_hex(right_str));
    libff::bit_vector expected_bits =
        libff::bit_vector(libzeth::bit_vector_from_hex(expected_str));

    left.fill_with_bits(pb, left_bits);
    right.fill_with_bits(pb, right_bits);

    libsnark::digest_variable<Field> result(
        pb, HashT::get_digest_len(), "result");

    libsnark::block_variable<Field> input_block(
        pb, {left, right}, "Block_variable");

    libzeth::sha256_ethereum<Field> hasher(
        pb, ZERO, input_block, result, "Sha256_ethereum");

    hasher.generate_r1cs_constraints(true);
    hasher.generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);

    std::ostream &stream = std::cout;
    std::cout << " -- left -- " << std::endl;
    dump_bit_vector(stream, left.get_bits(pb));
    std::cout << " -- right -- " << std::endl;
    dump_bit_vector(stream, right.get_bits(pb));
    std::cout << " -- Result digest -- " << std::endl;
    dump_bit_vector(stream, result.get_digest());
    std::cout << " -- Expected digest -- " << std::endl;
    dump_bit_vector(stream, expected_bits);

    ASSERT_EQ(result.get_digest(), expected_bits);
};

} // namespace

int main(int argc, char **argv)
{
    // /!\ WARNING: Do once for all tests. Do not
    // forget to do this !!!!
    pp::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
