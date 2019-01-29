#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Header to use the sha256_ethereum gadget
#include "sha256_ethereum.hpp"

#include "util.hpp"

#include "commitments.tcc"

using namespace libsnark;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT; // Should be alt_bn128 in the CMakeLists.txt
typedef sha256_ethereum<FieldT> HashT; // We use our hash function to do the tests

namespace {

libff::bit_vector generate_digests(int digest_len)
{
    libff::bit_vector digest_bits;
    srand(time(0));
    for (int i = 0; i < digest_len; i++)
    {
        digest_bits.push_back(rand() % 2);
    }

    return digest_bits;
}

void dump_bit_vector(std::ostream &out, const libff::bit_vector &v)
{
    out << "{";
    for (size_t i = 0; i < v.size() - 1; ++i)
    {
        out << v[i] << ", ";
    }
    out << v[v.size() - 1] << "}\n";
}

TEST(TestCOMMs, TestGet128bits) {
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb);
    pb.val(ZERO) = FieldT::zero();

    libsnark::pb_variable_array<FieldT> input = from_bits(
        {
            1, 1, 1, 1, 0, 0, 0, 0, // 1,1,1,1,0,0,0,0
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 1, 1, 1, 1 // 0,0,0,0,1,1,1,1
        }, ZERO
    );

    libsnark::pb_variable_array<FieldT> expected = from_bits(
        {
            1, 1, 1, 1, 0, 0, 0, 0, // 1,1,1,1,0,0,0,0
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0
        }, ZERO
    );

    libsnark::pb_variable_array<FieldT> result = get128bits<FieldT>(input);
    ASSERT_EQ(result.get_bits(pb), expected.get_bits(pb));
};

TEST(TestCOMMs, TestGetRightSideCMCOMM) {
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb);
    pb.val(ZERO) = FieldT::zero();

    // 64 bits
    libsnark::pb_variable_array<FieldT> input_value = from_bits(
        {
            1, 1, 1, 1, 0, 0, 0, 0, // 1,1,1,1,0,0,0,0
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0
        }, ZERO
    );

    // 192 zero bits
    libsnark::pb_variable_array<FieldT> expected = from_bits(
        {
            // 192 zero bits
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,

            // 64 bits of the value
            1, 1, 1, 1, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0
        }, ZERO
    );

    libsnark::pb_variable_array<FieldT> result = getRightSideCMCOMM<FieldT>(ZERO, input_value);
    ASSERT_EQ(result.get_bits(pb), expected.get_bits(pb));
};

TEST(TestCOMMs, TestCOMMInnerKGadget) {
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb);
    pb.val(ZERO) = FieldT::zero();

    // a_sk corresponds to the number: 0x0F00000000000FF00000000000000FF00000000000000FF00000000000000FF
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
        }, ZERO
    );

    // hex: 0xCF0000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> rho = from_bits(
        {
            1, 1, 0, 0, 1, 1, 1, 1,
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            1, 1, 1, 1, 1, 1, 1, 1, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            1, 1, 1, 1, 1, 1, 1, 1, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            1, 1, 1, 1, 1, 1, 1, 1, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            1, 1, 1, 1, 1, 1, 1, 1
        }, ZERO
    );

    // inner_k should equal: 
    // inner_k = sha256(a_pk || rho)
    // 
    // The hex of rho is: 0x0F0000000000FF00000000000000FF00000000000000FF00000000000000FF
    // 
    // Note: This test vector has been generated by using the solidity sha256 function
    // (we want to make sure that we generate the same digests both on-chain and off-chain)
    // Test vector generated with solidity v0.5.0
    char* inner_k_str = "2dddb81f2794e10b2932a4905eb20af14d91c728858392f610f78b12316378d0";
    libsnark::pb_variable_array<FieldT> inner_k_expected = from_bits(
        hexadecimal_digest_to_binary_vector(inner_k_str), 
        ZERO
    );

    std::shared_ptr<libsnark::digest_variable<FieldT>> result;
    result.reset(new digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<COMM_inner_k_gadget<FieldT> > comm_inner_k_gadget;
    comm_inner_k_gadget.reset(new COMM_inner_k_gadget<FieldT>(
        pb,
        ZERO,
        a_pk,
        rho,
        result)
    );

    comm_inner_k_gadget->generate_r1cs_constraints();
    comm_inner_k_gadget->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);

    ASSERT_EQ(result->get_digest(), inner_k_expected.get_bits(pb));
};

TEST(TestCOMMs, TestCOMMOuterKGadget) {
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb);
    pb.val(ZERO) = FieldT::zero();

    // 384 bits
    // hex string: 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF
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
        }, ZERO
    );

    // hex: 0xEF0000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> inner_k = from_bits(
        {
            // First 16bytes (128bits) // hex: 0xEF0000000000FF00000000000000FF00
            1, 1, 1, 0, 1, 1, 1, 1,
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            1, 1, 1, 1, 1, 1, 1, 1, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            1, 1, 1, 1, 1, 1, 1, 1,

            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            1, 1, 1, 1, 1, 1, 1, 1, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            1, 1, 1, 1, 1, 1, 1, 1
        }, ZERO
    );

    // outer_k should equal: 
    // outer_k = sha256(r || [inner_commitment]_128)
    // 
    // Hex of the 384 bits of the trap_r: "0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF"
    // Hex of the first 128bits of the inner_k: "0xEF0000000000FF00000000000000FF00"
    //
    // Note: This test vector has been generated by using the solidity sha256 function
    // (we want to make sure that we generate the same digests both on-chain and off-chain)
    char* outer_k_str = "2f511c3e6281ccfac6fd5d9118e7cc3b0e6c1923152fc337f157043893f92118";
    libsnark::pb_variable_array<FieldT> outer_k_expected = from_bits(
        hexadecimal_digest_to_binary_vector(outer_k_str), 
        ZERO
    );

    std::shared_ptr<libsnark::digest_variable<FieldT>> result;
    result.reset(new digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<COMM_outer_k_gadget<FieldT> > comm_outer_k_gadget;
    comm_outer_k_gadget.reset(new COMM_outer_k_gadget<FieldT>(
        pb,
        ZERO,
        trap_r,
        inner_k,
        result)
    );

    comm_outer_k_gadget->generate_r1cs_constraints();
    comm_outer_k_gadget->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);

    ASSERT_EQ(result->get_digest(), outer_k_expected.get_bits(pb));
};

TEST(TestCOMMs, TestCOMMCMGadget) {
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb);
    pb.val(ZERO) = FieldT::zero();

    // hex: 0xAF0000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> outer_k = from_bits(
        {
            1, 0, 1, 0, 1, 1, 1, 1,
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            1, 1, 1, 1, 1, 1, 1, 1, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            1, 1, 1, 1, 1, 1, 1, 1,
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            1, 1, 1, 1, 1, 1, 1, 1, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            1, 1, 1, 1, 1, 1, 1, 1
        }, ZERO
    );

    // 64 bits for the value
    // hex: 0x2F0000000000000F
    libsnark::pb_variable_array<FieldT> value = from_bits(
        {
            0, 0, 1, 0, 1, 1, 1, 1,
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 1, 1, 1, 1
        }, ZERO
    );

    // cm should equal: 
    // cm = sha256(outer_k || 0^192 || value_v)
    //
    // The hex value of '0^192 || value_v' is 0x00000000000000000000000000000000000000000000002F0000000000000F
    //
    // Note: This test vector has been generated by using the solidity sha256 function
    // (we want to make sure that we generate the same digests both on-chain and off-chain)
    // Solidity version used: v0.5.0
    char* cm_str = "86af18de128d38ec362f754871894278b804ea64adf681ba4f1de8658fe6cf40";
    libsnark::pb_variable_array<FieldT> cm_expected = from_bits(
        hexadecimal_digest_to_binary_vector(cm_str), 
        ZERO
    );

    std::shared_ptr<libsnark::digest_variable<FieldT>> result;
    result.reset(new digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<COMM_cm_gadget<FieldT> > comm_cm_gadget;
    comm_cm_gadget.reset(new COMM_cm_gadget<FieldT>(
        pb,
        ZERO,
        outer_k,
        value,
        result)
    );

    comm_cm_gadget->generate_r1cs_constraints();
    comm_cm_gadget->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);

    ASSERT_EQ(result->get_digest(), cm_expected.get_bits(pb));
};

} // namespace

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}