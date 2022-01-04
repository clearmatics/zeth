// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/circuits/commitments/commitment.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/zeth_constants.hpp"
#include "zeth_config.h"

#include <gtest/gtest.h>
#include <libsnark/common/data_structures/merkle_tree.hpp>

using namespace libzeth;

using pp = defaults::pp;
using Field = defaults::Field;

// Instantiation of the templates for the tests
using Hash = BLAKE2s_256<Field>;

namespace
{

TEST(TestCOMMs, TestCOMMGadget)
{
    libsnark::protoboard<Field> pb;
    libsnark::pb_variable<Field> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = Field::zero();

    bits256 trap_r_bits256 = bits256::from_hex(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF");
    bits64 value_bits64 = bits64::from_hex("2F0000000000000F");
    bits256 rho_bits256 = bits256::from_hex(
        "FFFF000000000000000000000000000000000000000000000000000000009009");
    bits256 a_pk_bits256 = bits256::from_hex(
        "5c36fea42b82800d74304aa4f875142b421b4f2847e7c41c1077fbbcfd63f886");
    Field cm =
        Field("5198426621382268363215668966254183876371659610992196341185343716"
              "6529959660400");

    // hex: 0xAF000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<Field> a_pk;
    a_pk.allocate(pb, ZETH_A_PK_SIZE, "a_pk");
    a_pk.fill_with_bits(pb, a_pk_bits256.to_vector());

    libsnark::pb_variable_array<Field> rho;
    rho.allocate(pb, ZETH_RHO_SIZE, "rho");
    rho.fill_with_bits(pb, rho_bits256.to_vector());

    libsnark::pb_variable_array<Field> r;
    r.allocate(pb, ZETH_R_SIZE, "r");
    r.fill_with_bits(pb, trap_r_bits256.to_vector());

    libsnark::pb_variable_array<Field> v;
    v.allocate(pb, ZETH_V_SIZE, "v");
    v.fill_with_bits(pb, value_bits64.to_vector());

    libsnark::pb_variable<Field> result;
    result.allocate(pb, "result");

    COMM_cm_gadget<Field, Hash> comm_cm_gadget(pb, a_pk, rho, r, v, result);
    comm_cm_gadget.generate_r1cs_constraints();
    comm_cm_gadget.generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);

    ASSERT_EQ(pb.val(result), cm);
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
