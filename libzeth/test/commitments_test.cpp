// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "gtest/gtest.h"
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to get the constants
#include "zeth.h"

// Header to use the merkle tree data structure
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Header to use the blake2s gadget
#include "libzeth/circuits/blake2s/blake2s.hpp"

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
typedef BLAKE2s_256<FieldT> HashT;

namespace
{

TEST(TestCOMMs, TestCOMMGadget)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    bits256 trap_r_bits256 = hex_digest_to_bits256(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF");
    bits64 value_bits64 = hex_value_to_bits64("2F0000000000000F");
    bits256 rho_bits256 =
        hex_digest_to_bits256("FFFF000000000000000000000000000000"
                              "000000000000000000000000009009");
    bits256 a_pk_bits256 =
        hex_digest_to_bits256("5c36fea42b82800d74304aa4f875142b42"
                              "1b4f2847e7c41c1077fbbcfd63f886");
    FieldT cm = FieldT("5198426621382268363215668966254183876371659610992196341"
                       "1853437166529959660400");

    // hex: 0xAF000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> a_pk;
    a_pk.allocate(pb, ZETH_A_PK_SIZE, "a_pk");
    a_pk.fill_with_bits(pb, get_vector_from_bits256(a_pk_bits256));

    libsnark::pb_variable_array<FieldT> rho;
    rho.allocate(pb, ZETH_RHO_SIZE, "rho");
    rho.fill_with_bits(pb, get_vector_from_bits256(rho_bits256));

    libsnark::pb_variable_array<FieldT> r;
    r.allocate(pb, ZETH_R_SIZE, "r");
    r.fill_with_bits(pb, get_vector_from_bits256(trap_r_bits256));

    libsnark::pb_variable_array<FieldT> v;
    v.allocate(pb, ZETH_V_SIZE, "v");
    v.fill_with_bits(pb, get_vector_from_bits64(value_bits64));

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
