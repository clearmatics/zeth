#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Used to instantiate our templates
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libff/algebra/curves/public_params.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

// Header to use the sha256_ethereum gadget
#include "circuits/sha256/sha256_ethereum.hpp"

// Access the `from_bits` function and other utils
#include "circuits/circuits-util.hpp"
#include "util.hpp"

// Gadget to test
#include "circuits/prfs/prfs.hpp"

using namespace libsnark;
using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT; // Should be alt_bn128 in the CMakeLists.txt
typedef sha256_ethereum<FieldT> HashT; // We use our hash function to do the tests

namespace {

TEST(TestPRFs, TestGenZeroes) {
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb);
    pb.val(ZERO) = FieldT::zero();

    libsnark::pb_variable_array<FieldT> zeroes256 = from_bits(
        {
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
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0
        }, ZERO
    );

    libsnark::pb_variable_array<FieldT> result = gen256zeroes<FieldT, HashT>(ZERO);
    ASSERT_EQ(result.get_bits(pb), zeroes256.get_bits(pb));
};

TEST(TestPRFs, TestGetRightSideNFPRF) {
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb);
    pb.val(ZERO) = FieldT::zero();

    // hex: 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> rho = from_bits(
        {
            0, 0, 0, 0, 1, 1, 1, 1, // 0, 0, 0, 0, 1, 1, 1, 1,
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

    // hex: 0x43C000000000003FC00000000000003FC00000000000003FC00000000000003F
    libsnark::pb_variable_array<FieldT> expected = from_bits(
        {
            0, 1, 0, 0, 0, 0, 1, 1, //  (0, 1 is the right prefix here)
            1, 1, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 1, 1, 1, 1, 1, 1, 
            1, 1, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 1, 1, 1, 1, 1, 1, 
            1, 1, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 1, 1, 1, 1, 1, 1, 
            1, 1, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1, 1, 1, 1, 1, 1
        }, ZERO
    );

    libsnark::pb_variable_array<FieldT> result = getRightSideNFPRF<FieldT, HashT>(ZERO, rho);
    ASSERT_EQ(result.get_bits(pb), expected.get_bits(pb));
};

TEST(TestPRFs, TestPRFAddrApkGadget) {
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb);
    pb.val(ZERO) = FieldT::zero();

    // a_sk corresponds to the number: 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> a_sk = from_bits(
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

    // a_pk should equal: 0xa8bdcd1403ea97e088094d7c085c843b4f5895487f5827b3046b2e0328f5f58e
    // Since a_pk = sha256(a_sk || 0^256), where:
    // - a_sk = 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    // - 0^256 = 0x0000000000000000000000000000000000000000000000000000000000000000
    // 
    // Note: This test vector has been generated by using the solidity sha256 function
    // (we want to make sure that we generate the same digests both on-chain and off-chain)
    libsnark::pb_variable_array<FieldT> a_pk_expected = from_bits(
        hexadecimal_digest_to_binary_vector("a8bdcd1403ea97e088094d7c085c843b4f5895487f5827b3046b2e0328f5f58e"), 
        ZERO
    );

    std::shared_ptr<libsnark::digest_variable<FieldT>> result;
    result.reset(new digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<PRF_addr_a_pk_gadget<FieldT, HashT> > prf_apk_gadget;
    prf_apk_gadget.reset(new PRF_addr_a_pk_gadget<FieldT, HashT>(
        pb,
        ZERO,
        a_sk,
        result)
    );

    prf_apk_gadget->generate_r1cs_constraints();
    prf_apk_gadget->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);
    ASSERT_EQ(result->get_digest(), a_pk_expected.get_bits(pb));
};

TEST(TestPRFs, TestPRFNFGadget) {
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb);
    pb.val(ZERO) = FieldT::zero();

    // a_sk corresponds to the number: 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> a_sk = from_bits(
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

    // hex: 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    libsnark::pb_variable_array<FieldT> rho = from_bits(
        {
            0, 0, 0, 0, 1, 1, 1, 1, // 0, 0, 0, 0, 1, 1, 1, 1,
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

    // nf should equal: 
    // nf = sha256(a_sk || 01 || [rho]_254)
    // 
    // a_sk: 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    // rho:  0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF
    // '01 || [rho]_254': 0x43C000000000003FC00000000000003FC00000000000003FC00000000000003F
    // 
    // Note: This test vector has been generated by using the solidity sha256 function
    // (we want to make sure that we generate the same digests both on-chain and off-chain)
    libsnark::pb_variable_array<FieldT> nf_expected = from_bits(
        hexadecimal_digest_to_binary_vector("a4cc8f23d1dfeab58d7af00b3422f22dd60b9c608af5f30744073653236562c3"), 
        ZERO
    );

    std::shared_ptr<libsnark::digest_variable<FieldT>> result;
    result.reset(new digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));

    std::shared_ptr<PRF_nf_gadget<FieldT, HashT>> prf_nf_gadget;
    prf_nf_gadget.reset(new PRF_nf_gadget<FieldT, HashT>(
        pb,
        ZERO,
        a_sk,
        rho,
        result)
    );

    prf_nf_gadget->generate_r1cs_constraints();
    prf_nf_gadget->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    ASSERT_TRUE(is_valid_witness);
    ASSERT_EQ(result->get_digest(), nf_expected.get_bits(pb));
};

} // namespace

int main(int argc, char **argv) {
    ppT::init_public_params(); // /!\ WARNING: Do once for all tests. Do not forget to do this !!!!
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}