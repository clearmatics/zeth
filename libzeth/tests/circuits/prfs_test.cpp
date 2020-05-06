// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/circuits/prfs/prf.hpp"
#include "libzeth/core/utils.hpp"

#include <gtest/gtest.h>
#include <libsnark/common/data_structures/merkle_tree.hpp>

using namespace libsnark;
using namespace libzeth;

using ppT = libzeth::ppT;
using FieldT = libff::Fr<ppT>;

// We use our hash function to do the tests
using HashT = BLAKE2s_256<FieldT>;

namespace
{

TEST(TestPRFs, TestGenZeroes)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> zero;
    zero.allocate(pb, "zero");
    pb.val(zero) = FieldT::zero();

    libsnark::pb_variable_array<FieldT> zeroes256 =
        variable_array_from_bit_vector(
            {
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
            },
            zero);

    libsnark::pb_variable_array<FieldT> result =
        gen_256_zeroes<FieldT, HashT>(zero);
    ASSERT_EQ(result.get_bits(pb), zeroes256.get_bits(pb));
};

TEST(TestPRFs, TestPRFAddrApkGadget)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> zero;
    zero.allocate(pb, "zero");
    pb.val(zero) = FieldT::zero();

    // a_sk corresponds to the number:
    // 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> a_sk = variable_array_from_bit_vector(
        {
            false, false, false, false, true,  true,  true,  true,  // 0F
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true   // FF
        },
        zero);

    // a_pk should equal:
    // 0x208f95ee37621c3c2d9c74be39bf687c47e84c679b88df270858067c08a16daf Since
    // a_pk = blake2s( 1100 || [a_sk]_252 || 0^256), where:
    //  - a_sk =
    //   0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    //  - 0^256 =
    //   0x0000000000000000000000000000000000000000000000000000000000000000
    //   Note:
    // This test vector has been generated by using the hashlib blake2s
    // function Note: (we want to make sure that we generate the same digests
    // both on-chain and off-chain)
    libsnark::pb_variable_array<FieldT> a_pk_expected =
        variable_array_from_bit_vector(
            bit_vector_from_hex("2390c9e5370be7355f220b29caf3912ef970d828b73976"
                                "ae9bfeb1402ce4c1f9"),
            zero);

    std::shared_ptr<libsnark::digest_variable<FieldT>> result;
    result.reset(
        new digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<PRF_addr_a_pk_gadget<FieldT, HashT>> prf_apk_gadget;
    prf_apk_gadget.reset(
        new PRF_addr_a_pk_gadget<FieldT, HashT>(pb, zero, a_sk, result));

    prf_apk_gadget->generate_r1cs_constraints();
    prf_apk_gadget->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);
    ASSERT_EQ(result->get_digest(), a_pk_expected.get_bits(pb));
};

TEST(TestPRFs, TestPRFNFGadget)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> zero;
    zero.allocate(pb, "zero");
    pb.val(zero) = FieldT::zero();

    // a_sk corresponds to the number:
    // 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> a_sk = variable_array_from_bit_vector(
        {
            false, false, false, false, true,  true,  true,  true,  // 0F
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true   // FF
        },
        zero);

    // hex: 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> rho = variable_array_from_bit_vector(
        {
            false, false, false, false, true,  true,  true,  true,  // 0F
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            true,  true,  true,  true,  true,  true,  true,  true   // FF
        },
        zero);

    // nf should equal:
    // 4a5f4f585dda39cc597366f9172bae924d22e832487e12e76742dbab9393b620
    // nf = blake2sCompress( 1110 || [a_sk]_252 || rho)
    // a_sk:
    // 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    // rho:
    // 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    // Note: This test vector has been generated by using the hashlib
    // blake2s function (we want to make sure that we generate the same digests
    // both on-chain and off-chain)
    libsnark::pb_variable_array<FieldT> nf_expected =
        variable_array_from_bit_vector(
            bit_vector_from_hex("ea43866d185e1bdb84713b699a2966d929d1392488c010"
                                "c603e46a4cb92986f8"),
            zero);

    std::shared_ptr<libsnark::digest_variable<FieldT>> result;
    result.reset(
        new digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<PRF_nf_gadget<FieldT, HashT>> prf_nf_gadget;
    prf_nf_gadget.reset(
        new PRF_nf_gadget<FieldT, HashT>(pb, zero, a_sk, rho, result));

    prf_nf_gadget->generate_r1cs_constraints();
    prf_nf_gadget->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);
    ASSERT_EQ(result->get_digest(), nf_expected.get_bits(pb));
};

TEST(TestPRFs, TestPRFPKGadget)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> zero;
    zero.allocate(pb, "zero");
    pb.val(zero) = FieldT::zero();

    // a_sk corresponds to the number:
    // 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> a_sk = variable_array_from_bit_vector(
        {
            false, false, false, false, true,  true,  true,  true,  // 0F
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true   // FF
        },
        zero);

    // h_sig: 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> hsig = variable_array_from_bit_vector(
        {
            false, false, false, false, true,  true,  true,  true,  // 0F
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            true,  true,  true,  true,  true,  true,  true,  true   // FF
        },
        zero);

    // h_i should equal:
    // 7ea1525fdbf9462c5144796937e1f80b9dad42369f7d4987c436b2f79257f9ac h_i =
    // blake2sCompress( 0i00 || [a_sk]_252 || h_sig)
    // a_sk =
    // 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    // h_sig =
    // 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    // Note: This test vector has been generated by using the hashlib
    // blake2s function (we want to make sure that we generate the same digests
    // both on-chain and off-chain)
    libsnark::pb_variable_array<FieldT> h_expected0 =
        variable_array_from_bit_vector(
            bit_vector_from_hex("8527fb92081cf832659a188163287f98b8c919401ba619"
                                "d6ebd30dc0f1aedeff"),
            zero);

    std::shared_ptr<libsnark::digest_variable<FieldT>> result0;
    result0.reset(
        new digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<PRF_pk_gadget<FieldT, HashT>> prf_pk_gadget0;
    prf_pk_gadget0.reset(new PRF_pk_gadget<FieldT, HashT>(
        pb, zero, a_sk, hsig, size_t(0), result0));

    prf_pk_gadget0->generate_r1cs_constraints();
    prf_pk_gadget0->generate_r1cs_witness();

    libsnark::pb_variable_array<FieldT> h_expected1 =
        variable_array_from_bit_vector(
            bit_vector_from_hex("aea510673ff50225bec4bd918c102ea0c9b117b9353464"
                                "4ee70b74522b204b29"),
            zero);

    std::shared_ptr<libsnark::digest_variable<FieldT>> result1;
    result1.reset(
        new digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<PRF_pk_gadget<FieldT, HashT>> prf_pk_gadget1;
    prf_pk_gadget1.reset(new PRF_pk_gadget<FieldT, HashT>(
        pb, zero, a_sk, hsig, size_t(1), result1));

    prf_pk_gadget1->generate_r1cs_constraints();
    prf_pk_gadget1->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);
    ASSERT_EQ(result0->get_digest(), h_expected0.get_bits(pb));
    ASSERT_EQ(result1->get_digest(), h_expected1.get_bits(pb));
};

TEST(TestPRFs, TestPRFRhoGadget)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> zero;
    zero.allocate(pb, "zero");
    pb.val(zero) = FieldT::zero();

    // phi corresponds to the number:
    // 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> phi = variable_array_from_bit_vector(
        {
            false, false, false, false, true,  true,  true,  true,  // 0F
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            false, false, false, false, false, false, false, false, // 00
            true,  true,  true,  true,  true,  true,  true,  true   // FF
        },
        zero);

    // hsig: 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> hsig = variable_array_from_bit_vector(
        {
            false, false, false, false, true,  true,  true,  true,  // 0F
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            true,  true,  true,  true,  true,  true,  true,  true,  // FF
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            false, false, false, false, false, false, false, false, //
            true,  true,  true,  true,  true,  true,  true,  true   // FF
        },
        zero);

    // rho should equal:
    // a87c47a6c721bdbbb4aa8875c2aa72d4db31b9526aa920656049e00786f7f8a4
    // rho = blake2sCompress( 0i10 || [phi]_252 || h_sig) phi:
    // 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF hsig:
    // 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF Note:
    // This test vector has been generated by using the hashlib blake2s
    // function (we want to make sure that we generate the same digests both
    // on-chain and off-chain)
    libsnark::pb_variable_array<FieldT> rho_expected0 =
        variable_array_from_bit_vector(
            bit_vector_from_hex("d7b7c4536bbba1aaca684706ba0df170af95515d573ad9"
                                "3e30015e1c40ebc539"),
            zero);

    std::shared_ptr<libsnark::digest_variable<FieldT>> result0;
    result0.reset(
        new digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<PRF_rho_gadget<FieldT, HashT>> prf_rho_gadget0;
    prf_rho_gadget0.reset(new PRF_rho_gadget<FieldT, HashT>(
        pb, zero, phi, hsig, size_t(0), result0));

    prf_rho_gadget0->generate_r1cs_constraints();
    prf_rho_gadget0->generate_r1cs_witness();

    libsnark::pb_variable_array<FieldT> rho_expected1 =
        variable_array_from_bit_vector(
            bit_vector_from_hex("bb17f6088e47a8b2ac8e3d57588d52fed63079dc2b7045"
                                "561d6d5e7288384249"),
            zero);

    std::shared_ptr<libsnark::digest_variable<FieldT>> result1;
    result1.reset(
        new digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<PRF_rho_gadget<FieldT, HashT>> prf_rho_gadget1;
    prf_rho_gadget1.reset(new PRF_rho_gadget<FieldT, HashT>(
        pb, zero, phi, hsig, size_t(1), result1));

    prf_rho_gadget1->generate_r1cs_constraints();
    prf_rho_gadget1->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);
    ASSERT_EQ(result0->get_digest(), rho_expected0.get_bits(pb));
    ASSERT_EQ(result1->get_digest(), rho_expected1.get_bits(pb));
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
