// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "gtest/gtest.h"
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure
#include "libzeth/types/merkle_tree_field.hpp"

// Header to use the blake2s gadget
#include "libzeth/circuits/blake2s/blake2s_comp.hpp"

// Access the `from_bits` function and other utils
#include "libzeth/circuits/circuits-utils.hpp"
#include "libzeth/util.hpp"

// Access the defined constants
#include "libzeth/zeth.h"

// Bring the types in scope
#include "libzeth/types/bits.hpp"
#include "libzeth/types/note.hpp"

// Gadget to test
#include "libzeth/circuits/notes/note.hpp"

using namespace libzeth;

typedef libff::default_ec_pp ppT;

// Should be alt_bn128 in the CMakeLists.txt
typedef libff::Fr<ppT> FieldT;

// We use our hash functions to do the tests
typedef BLAKE2s_256_comp<FieldT> HashT;
typedef MiMC_mp_gadget<FieldT> HashTreeT;
static const size_t TreeDepth = 4;

namespace
{

TEST(TestNoteCircuits, TestInputNoteGadget)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    libff::enter_block(
        "Initialize the coins' data (nullifier, a_sk and a_pk, cm, rho)", true);
    bits384 trap_r_bits384 = get_bits384_from_vector(hex_to_binary_vector(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00"
        "000000000000FF00000000000000FF"));
    bits64 value_bits64 =
        get_bits64_from_vector(hex_to_binary_vector("2F0000000000000F"));
    bits256 a_sk_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "FF0000000000000000000000000000000000000000000000000000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "FFFF000000000000000000000000000000000000000000000000000000009009"));

    // Get a_pk from a_sk (PRF)
    //
    // 1100 || [a_sk]_252 =
    // 0xCFF0000000000000000000000000000000000000000000000000000000000000
    // 0^256 =
    // 0x0000000000000000000000000000000000000000000000000000000000000000
    // a_pk = blake2sCompress( 1100 || [a_sk]_252 || 0^256)
    // Generated directly from a_sk and hashlib blake2s
    bits256 a_pk_bits256 = get_bits256_from_vector(
        hex_digest_to_binary_vector("f172d7299ac8ac974ea59413e4a8769182"
                                    "6df038ba24a2b52d5c5d15c2cc8c49"));

    // Get nf from a_sk and rho (PRF)
    //
    // nf = blake2sCompress( 1110 || [a_sk]_252 || rho)
    // 1110 || [a_sk]_252 =
    // 0xEFF0000000000000000000000000000000000000000000000000000000000000
    // rho = FFFF000000000000000000000000000000000000000000000000000000009009
    // The test vector generated directly from a_sk and hashlib blake2s, gives:
    bits256 nf_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "ff2f41920346251f6e7c67062149f98bc90c915d3d3020927ca01deab5da0fd7"));

    // Get the coin's commitment (COMM)
    //
    // inner_k = blake2sCompress(a_pk || rho)
    // outer_k = blake2sCompress(r || [inner_commitment]_128)
    // cm = blake2sCompress(outer_k || 0^192 || value_v)
    // Converted from old hex string
    // "c8095fff642b3eba57f195ef3e27dcf424b470a22a3bb05704836cda21249d66"
    // (big-endian)
    FieldT cm_field = FieldT("9047913389147464750130699723564635396506448356890"
                             "6678810249472230384841563494");
    libff::leave_block(
        "Initialize the coins' data (nullifier, a_sk and a_pk, cm, rho)", true);

    libff::enter_block(
        "Setup a local merkle tree and append our commitment to it", true);
    std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>> test_merkle_tree =
        std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>>(
            new merkle_tree_field<FieldT, HashTreeT>(TreeDepth));

    // In practice the address is emitted by the mixer contract once the
    // commitment is appended to the tree
    const size_t address_commitment = 1;
    libff::bit_vector address_bits;
    for (size_t i = 0; i < TreeDepth; ++i) {
        address_bits.push_back((address_commitment >> i) & 0x1);
    }

    test_merkle_tree->set_value(address_commitment, cm_field);

    // Get the root of the new/non-empty tree (after insertion)
    FieldT updated_root_value = test_merkle_tree->get_root();

    libff::leave_block(
        "Setup a local merkle tree and append our commitment to it", true);

    libff::enter_block(
        "Data conversion to generate a witness of the note gadget", true);

    std::shared_ptr<libsnark::digest_variable<FieldT>> a_sk_digest;
    a_sk_digest.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), "a_sk_digest"));
    a_sk_digest->generate_r1cs_constraints();
    a_sk_digest->generate_r1cs_witness(
        libff::bit_vector(get_vector_from_bits256(a_sk_bits256)));

    std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier_digest;
    nullifier_digest.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), "nullifier_digest"));
    nullifier_digest->generate_r1cs_constraints();
    nullifier_digest->generate_r1cs_witness(
        libff::bit_vector(get_vector_from_bits256(nf_bits256)));

    std::shared_ptr<libsnark::pb_variable<FieldT>> merkle_root;
    merkle_root.reset(new libsnark::pb_variable<FieldT>);
    (*merkle_root).allocate(pb, "root");
    pb.val(*merkle_root) = updated_root_value;

    std::shared_ptr<input_note_gadget<FieldT, HashT, HashTreeT, TreeDepth>>
        input_note_g = std::shared_ptr<
            input_note_gadget<FieldT, HashT, HashTreeT, TreeDepth>>(
            new input_note_gadget<FieldT, HashT, HashTreeT, TreeDepth>(
                pb, ZERO, a_sk_digest, nullifier_digest, *merkle_root));

    // Get the merkle path to the commitment we appended
    std::vector<FieldT> path = test_merkle_tree->get_path(address_commitment);

    // Create a note from the coin's data
    zeth_note note(a_pk_bits256, value_bits64, rho_bits256, trap_r_bits384);

    input_note_g->generate_r1cs_constraints();
    input_note_g->generate_r1cs_witness(path, address_bits, note);
    libff::leave_block(
        "Data conversion to generate a witness of the note gadget", true);

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "************* SAT result: " << is_valid_witness
              << " ******************" << std::endl;

    ASSERT_TRUE(is_valid_witness);
};

TEST(TestNoteCircuits, TestOutputNoteGadget)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    libff::enter_block(
        "Initialize the output coins' data (a_pk, cm, rho)", true);
    bits384 trap_r_bits384 = get_bits384_from_vector(hex_to_binary_vector(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00"
        "000000000000FF00000000000000FF"));
    bits64 value_bits64 =
        get_bits64_from_vector(hex_to_binary_vector("2F0000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "FFFF000000000000000000000000000000000000000000000000000000009009"));
    bits256 a_pk_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"));

    // Get the coin's commitment (COMM)
    //
    // inner_k = blake2sCompress(a_pk || rho)
    // outer_k = blake2sCompress(r || [inner_commitment]_128)
    // cm = blake2sCompress(outer_k || 0^192 || value_v)
    bits256 cm_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "626876b3e2747325f469df067b1f86c8474ffe85e97f56f273c5798dcfccd925"));
    libff::leave_block(
        "Initialize the output coins' data (a_pk, cm, rho)", true);

    libff::enter_block(
        "Data conversion to generate a witness of the note gadget", true);
    std::shared_ptr<libsnark::digest_variable<FieldT>> rho_digest;
    rho_digest.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), "rho_digest"));
    rho_digest->generate_r1cs_constraints();
    rho_digest->generate_r1cs_witness(
        libff::bit_vector(get_vector_from_bits256(rho_bits256)));

    std::shared_ptr<libsnark::digest_variable<FieldT>> commitment;
    commitment.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), "root_digest"));
    std::shared_ptr<output_note_gadget<FieldT, HashT>> output_note_g =
        std::shared_ptr<output_note_gadget<FieldT, HashT>>(
            new output_note_gadget<FieldT, HashT>(
                pb, ZERO, rho_digest, commitment));

    // Create a note from the coin's data
    zeth_note note(a_pk_bits256, value_bits64, rho_bits256, trap_r_bits384);

    output_note_g->generate_r1cs_constraints();
    output_note_g->generate_r1cs_witness(note);
    libff::leave_block(
        "Data conversion to generate a witness of the note gadget", true);

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "************* SAT result: " << is_valid_witness
              << " ******************" << std::endl;
    ASSERT_TRUE(is_valid_witness);

    // Last check to make sure the commitment computed is the expected one
    libff::bit_vector obtained_digest = commitment->get_digest();
    libff::bit_vector expected_digest =
        libff::bit_vector(get_vector_from_bits256(cm_bits256));
    ASSERT_EQ(obtained_digest, expected_digest);
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
