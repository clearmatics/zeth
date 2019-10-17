#include "gtest/gtest.h"
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Header to use the sha256_ethereum gadget
#include "circuits/sha256/sha256_ethereum.hpp"

// Access the `from_bits` function and other utils
#include "circuits/circuits-util.hpp"
#include "util.hpp"

// Get the gadget to test
#include "circuits/commitments/commitments.hpp"

using namespace libzeth;

// Instantiation of the templates for the tests
typedef libff::default_ec_pp ppT;
// Should be alt_bn128 in the CMakeLists.txt
typedef libff::Fr<ppT> FieldT;
// We use our hash function to do the tests
typedef sha256_ethereum<FieldT> HashT;

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

TEST(TestCOMMs, TestCOMMInnerKGadget)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    // hex: 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> a_pk = from_bits(
        {
            0, 0, 0, 0, 1, 1, 1, 1, // 0F
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            1, 1, 1, 1, 1, 1, 1, 1  // FF
        },
        ZERO);

    // hex: 0xCF000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> rho = from_bits(
        {
            1, 1, 0, 0, 1, 1, 1, 1, // CF
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            1, 1, 1, 1, 1, 1, 1, 1  // FF
        },
        ZERO);

    // inner_k should equal:
    // inner_k = sha256(a_pk || rho)
    //
    // a_pk: 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    // rho: 0xCF000000000000FF00000000000000FF00000000000000FF00000000000000FF
    //
    // Note: This test vector has been generated by using the solidity sha256
    // function (we want to make sure that we generate the same digests both
    // on-chain and off-chain) Test vector generated with solidity v0.5.0
    libsnark::pb_variable_array<FieldT> inner_k_expected = from_bits(
        hexadecimal_digest_to_binary_vector(
            "71367047d6873b02f3fd6a0b5a30ed8cf5df279e876e83da8286017641f3c402"),
        ZERO);

    std::shared_ptr<libsnark::digest_variable<FieldT>> result;
    result.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<COMM_inner_k_gadget<FieldT, HashT>> comm_inner_k_gadget;
    comm_inner_k_gadget.reset(
        new COMM_inner_k_gadget<FieldT, HashT>(pb, a_pk, rho, result));

    comm_inner_k_gadget->generate_r1cs_constraints();
    comm_inner_k_gadget->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);

    ASSERT_EQ(result->get_digest(), inner_k_expected.get_bits(pb));
};

TEST(TestCOMMs, TestCOMMOuterKGadget)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    // 384 bits
    // hex:
    // 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> trap_r = from_bits(
        {
            0, 0, 0, 0, 1, 1, 1, 1, // 0F
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            0, 0, 0, 0, 0, 0, 0, 0, // 00
            1, 1, 1, 1, 1, 1, 1, 1  // FF
        },
        ZERO);

    // hex: 0xEF000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> inner_k = from_bits(
        {
            // First 16bytes (128bits), hex: 0xEF000000000000FF00000000000000FF
            1, 1, 1, 0, 1, 1, 1, 1, // EF
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            1, 1, 1, 1, 1, 1, 1, 1, // FF

            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            1, 1, 1, 1, 1, 1, 1, 1, // FF
        },
        ZERO);

    // outer_k should equal:
    // outer_k = sha256(r || [inner_commitment]_128)
    //
    // Hex of the 384 bits of the trap_r:
    // "0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF"
    // Hex of the first 128bits of the inner_k:
    // "0xEF000000000000FF00000000000000FF"
    //
    // Note: This test vector has been generated by using the solidity sha256
    // function (we want to make sure that we generate the same digests both
    // on-chain and off-chain) hash generated with solidity v0.5.0:
    // ```
    // function hash(bytes memory left, bytes memory right) public pure returns
    // (bytes32) {
    //    return sha256(abi.encodePacked(left, right));
    // }
    // ```
    libsnark::pb_variable_array<FieldT> outer_k_expected = from_bits(
        hexadecimal_digest_to_binary_vector(
            "3bb028c826f54a3dcc6f7b774c887c5f7f6122a1cbbe5759415c9113408fe480"),
        ZERO);

    std::shared_ptr<libsnark::digest_variable<FieldT>> result;
    result.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<COMM_outer_k_gadget<FieldT, HashT>> comm_outer_k_gadget;
    comm_outer_k_gadget.reset(
        new COMM_outer_k_gadget<FieldT, HashT>(pb, trap_r, inner_k, result));

    comm_outer_k_gadget->generate_r1cs_constraints();
    comm_outer_k_gadget->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);

    ASSERT_EQ(result->get_digest(), outer_k_expected.get_bits(pb));
};

TEST(TestCOMMs, TestCOMMCMGadget)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    // hex: 0xAF000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> outer_k = from_bits(
        {
            1, 0, 1, 0, 1, 1, 1, 1, // AF
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            1, 1, 1, 1, 1, 1, 1, 1, // FF
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            1, 1, 1, 1, 1, 1, 1, 1  // FF
        },
        ZERO);

    // 64 bits for the value
    // hex: 0x2F0000000000000F
    libsnark::pb_variable_array<FieldT> value = from_bits(
        {
            0, 0, 1, 0, 1, 1, 1, 1, // 2F
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 1, 1, 1, 1  // 0F
        },
        ZERO);

    // cm should equal:
    // cm = sha256(outer_k || 0^192 || value_v)
    //
    // outer_k:
    // 0xAF000000000000FF00000000000000FF00000000000000FF00000000000000FF '0^192
    // || value_v':
    // 0x0000000000000000000000000000000000000000000000002F0000000000000F
    //
    // Note: This test vector has been generated by using the solidity sha256
    // function (we want to make sure that we generate the same digests both
    // on-chain and off-chain) Solidity version used: v0.5.0
    libsnark::pb_variable_array<FieldT> cm_expected = from_bits(
        hexadecimal_digest_to_binary_vector(
            "02c0ba7ad66ee30e178fa688791fd875a5e68f5a586a2f7bfceeccb29aad8b7b"),
        ZERO);

    std::shared_ptr<libsnark::digest_variable<FieldT>> result;
    result.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<COMM_cm_gadget<FieldT, HashT>> comm_cm_gadget;
    comm_cm_gadget.reset(
        new COMM_cm_gadget<FieldT, HashT>(pb, ZERO, outer_k, value, result));

    comm_cm_gadget->generate_r1cs_constraints();
    comm_cm_gadget->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);

    ASSERT_EQ(result->get_digest(), cm_expected.get_bits(pb));
};

TEST(TestCOMMs, TestCOMMALLCMGadget)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    bits384 trap_r_bits384 =
        get_bits384_from_vector(hexadecimal_str_to_binary_vector(
            "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00"
            "000000000000FF00000000000000FF"));
    bits64 value_bits64 = get_bits64_from_vector(
        hexadecimal_str_to_binary_vector("2F0000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(
        hexadecimal_digest_to_binary_vector("FFFF000000000000000000000000000000"
                                            "000000000000000000000000009009"));
    bits256 a_pk_bits256 = get_bits256_from_vector(
        hexadecimal_digest_to_binary_vector("5c36fea42b82800d74304aa4f875142b42"
                                            "1b4f2847e7c41c1077fbbcfd63f886"));

    bits256 inner_bits256 = get_bits256_from_vector(
        hexadecimal_digest_to_binary_vector("940de4dff75b94ec57867fefe16bfa9dca"
                                            "5ef2b4d649a407377b42ce23a9de83"));
    bits256 outer_bits256 = get_bits256_from_vector(
        hexadecimal_digest_to_binary_vector("a4f1c177d2a414e08c02ea86381a4a5c6f"
                                            "c512f4bac4808fd015b20c56bf07cd"));
    bits256 cm_bits256 = get_bits256_from_vector(
        hexadecimal_digest_to_binary_vector("a8ab7c0cccb5d4cc8680b8d542d6745ab2"
                                            "8d588e4dd6d40ee4d22cd7a544e74c"));

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

    std::shared_ptr<libsnark::digest_variable<FieldT>> inner;
    inner.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), "inner"));
    std::shared_ptr<libsnark::digest_variable<FieldT>> outer;
    outer.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), "outer"));
    std::shared_ptr<libsnark::digest_variable<FieldT>> result;
    result.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<COMM_inner_k_gadget<FieldT, HashT>> comm_inner_k_gadget;
    comm_inner_k_gadget.reset(
        new COMM_inner_k_gadget<FieldT, HashT>(pb, a_pk, rho, inner));
    comm_inner_k_gadget->generate_r1cs_constraints();
    comm_inner_k_gadget->generate_r1cs_witness();

    std::shared_ptr<COMM_outer_k_gadget<FieldT, HashT>> comm_outer_k_gadget;
    comm_outer_k_gadget.reset(
        new COMM_outer_k_gadget<FieldT, HashT>(pb, r, inner->bits, outer));
    comm_outer_k_gadget->generate_r1cs_constraints();
    comm_outer_k_gadget->generate_r1cs_witness();

    std::shared_ptr<COMM_cm_gadget<FieldT, HashT>> comm_cm_gadget;
    comm_cm_gadget.reset(
        new COMM_cm_gadget<FieldT, HashT>(pb, ZERO, outer->bits, v, result));
    comm_cm_gadget->generate_r1cs_constraints();
    comm_cm_gadget->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);

    ASSERT_EQ(inner->get_digest(), get_vector_from_bits256(inner_bits256));
    ASSERT_EQ(outer->get_digest(), get_vector_from_bits256(outer_bits256));
    ASSERT_EQ(result->get_digest(), get_vector_from_bits256(cm_bits256));
};

} // namespace

int main(int argc, char **argv)
{
    ppT::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
