// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/circuits/commitments/commitment.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/zeth_constants.hpp"

#include <gtest/gtest.h>
#include <libsnark/common/data_structures/merkle_tree.hpp>

using namespace libzeth;

// Instantiation of the templates for the tests
using ppT = libzeth::ppT;
using FieldT = libff::Fr<ppT>;
using HashT = BLAKE2s_256<FieldT>;

namespace
{

TEST(TestCOMMs, TestCOMMGadget)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> zero;
    zero.allocate(pb, "zero");
    pb.val(zero) = FieldT::zero();

    bits256 trap_r_bits256 = bits256_from_hex(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF");
    bits64 value_bits64 = bits64_from_hex("2F0000000000000F");
    bits256 rho_bits256 = bits256_from_hex(
        "FFFF000000000000000000000000000000000000000000000000000000009009");
    bits256 a_pk_bits256 = bits256_from_hex(
        "5c36fea42b82800d74304aa4f875142b421b4f2847e7c41c1077fbbcfd63f886");
    FieldT cm = FieldT(
        "5198426621382268363215668966254183876371659610992196341185343716"
        "6529959660400");

    // hex: 0xAF000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> a_pk;
    a_pk.allocate(pb, ZETH_A_PK_SIZE, "a_pk");
    a_pk.fill_with_bits(pb, bits256_to_vector(a_pk_bits256));

    libsnark::pb_variable_array<FieldT> rho;
    rho.allocate(pb, ZETH_RHO_SIZE, "rho");
    rho.fill_with_bits(pb, bits256_to_vector(rho_bits256));

    libsnark::pb_variable_array<FieldT> r;
    r.allocate(pb, ZETH_R_SIZE, "r");
    r.fill_with_bits(pb, bits256_to_vector(trap_r_bits256));

    libsnark::pb_variable_array<FieldT> v;
    v.allocate(pb, ZETH_V_SIZE, "v");
    v.fill_with_bits(pb, bits64_to_vector(value_bits64));

    libsnark::pb_variable<FieldT> result;
    result.allocate(pb, "result");

    std::shared_ptr<COMM_cm_gadget<FieldT, HashT>> comm_cm_gadget;
    comm_cm_gadget.reset(
        new COMM_cm_gadget<FieldT, HashT>(pb, a_pk, rho, r, v, result));

    comm_cm_gadget->generate_r1cs_constraints();

    comm_cm_gadget->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);

    ASSERT_EQ(pb.val(result), cm);
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
