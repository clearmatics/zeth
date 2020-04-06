// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "gtest/gtest.h"
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Header to use the blake2s gadget
#include "libzeth/circuits/blake2s/blake2s_comp.hpp"

// Access the `from_bits` function and other utils
#include "libzeth/circuits/circuits_utils.hpp"
#include "libzeth/util.hpp"

// Get the gadget to test
#include "libzeth/circuits/commitments/commitment.hpp"

using namespace libzeth;

// Instantiation of the templates for the tests
typedef libff::default_ec_pp ppT;

// Should be alt_bn128 in the CMakeLists.txt
typedef libff::Fr<ppT> FieldT;

// We use our hash function to do the tests
typedef BLAKE2s_256_comp<FieldT> HashT;

namespace
{

TEST(TestCOMMs, TestGet128bits)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    // hex: 0xF00000000000000000000000000000000000000000000000000000000000000F
    libsnark::pb_variable_array<FieldT> input = from_bits(
        {
            1, 1, 1, 1, 0, 0, 0, 0, // 1,1,1,1,0,0,0,0
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 1, 1, 1, 1, // 0,0,0,0,1,1,1,1
        },
        ZERO);

    // hex: 0xF0000000000000000000000000000000
    libsnark::pb_variable_array<FieldT> expected = from_bits(
        {
            1, 1, 1, 1, 0, 0, 0, 0, // 1,1,1,1,0,0,0,0
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0  //
        },
        ZERO);

    libsnark::pb_variable_array<FieldT> result = get128bits<FieldT>(input);
    ASSERT_EQ(result.get_bits(pb), expected.get_bits(pb));
};

TEST(TestCOMMs, TestGetRightSideCMCOMM)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    // 64 bits
    // hex: 0xF000000000000000
    libsnark::pb_variable_array<FieldT> input_value = from_bits(
        {
            1, 1, 1, 1, 0, 0, 0, 0, // 1,1,1,1,0,0,0,0
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0  //
        },
        ZERO);

    // 192 zero bits
    // hex: 0x000000000000000000000000000000000000000000000000 F000000000000000
    libsnark::pb_variable_array<FieldT> expected = from_bits(
        {
            0, 0, 0, 0, 0, 0, 0, 0, // 192 zero bits
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            1, 1, 1, 1, 0, 0, 0, 0, // 64 bits of the value
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0  //
        },
        ZERO);

    libsnark::pb_variable_array<FieldT> result =
        getRightSideCMCOMM<FieldT>(ZERO, input_value);
    ASSERT_EQ(result.get_bits(pb), expected.get_bits(pb));
};

TEST(TestCOMMs, TestCOMMGadget)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    bits384 trap_r_bits384 = hex_value_to_bits384(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00"
        "000000000000FF00000000000000FF");
    bits64 value_bits64 = hex_value_to_bits64("2F0000000000000F");
    bits256 rho_bits256 = hex_digest_to_bits256(
        "FFFF000000000000000000000000000000000000000000000000000000009009");
    bits256 a_pk_bits256 = hex_digest_to_bits256(
        "5c36fea42b82800d74304aa4f875142b421b4f2847e7c41c1077fbbcfd63f886");
    bits256 cm_bits256 = hex_digest_to_bits256(
        "f1378e66b0037337743d1ca5c83ed28c4e873c3fb242dcef3ff0db4ebe82c15f");

    // hex: 0xAF000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> a_pk;
    a_pk.allocate(pb, 256, "a_pk");
    a_pk.fill_with_bits(pb, get_vector_from_bits256(a_pk_bits256));

    libsnark::pb_variable_array<FieldT> rho;
    rho.allocate(pb, 256, "rho");
    rho.fill_with_bits(pb, get_vector_from_bits256(rho_bits256));

    libsnark::pb_variable_array<FieldT> r;
    r.allocate(pb, 384, "r");
    r.fill_with_bits(pb, get_vector_from_bits384(trap_r_bits384));

    libsnark::pb_variable_array<FieldT> v;
    v.allocate(pb, 64, "v");
    v.fill_with_bits(pb, get_vector_from_bits64(value_bits64));

    std::shared_ptr<libsnark::digest_variable<FieldT>> result;
    result.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<COMM_cm_gadget<FieldT, HashT>> comm_cm_gadget;
    comm_cm_gadget.reset(
        new COMM_cm_gadget<FieldT, HashT>(pb, ZERO, a_pk, rho, r, v, result));
    comm_cm_gadget->generate_r1cs_constraints();
    comm_cm_gadget->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);

    ASSERT_EQ(result->get_digest(), get_vector_from_bits256(cm_bits256));
};

} // namespace

int main(int argc, char **argv)
{
    // /!\ WARNING: Do once for all tests. Do not
    // forget to do this !!!!
    ppT::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
