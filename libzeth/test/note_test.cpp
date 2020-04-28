// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/circuits/notes/note.hpp"
#include "libzeth/types/bits.hpp"
#include "libzeth/types/merkle_tree_field.hpp"
#include "libzeth/types/note.hpp"
#include "libzeth/util.hpp"
#include "libzeth/zeth.h"

#include "gtest/gtest.h"

using namespace libzeth;

typedef libzeth::ppT ppT;

// Should be alt_bn128 in the CMakeLists.txt
typedef libff::Fr<ppT> FieldT;

// We use our hash functions to do the tests
typedef BLAKE2s_256<FieldT> HashT;
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
    bits256 trap_r_bits256 = get_bits256_from_hexadecimal_str(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF");
    bits64 value_bits64 = get_bits64_from_hexadecimal_str("2F0000000000000F");
    bits256 a_sk_bits256 = get_bits256_from_hexadecimal_str(
        "FF0000000000000000000000000000000000000000000000000000000000000F");
    bits256 rho_bits256 = get_bits256_from_hexadecimal_str(
        "FFFF000000000000000000000000000000000000000000000000000000009009");

    // Get a_pk from a_sk (PRF)
    //
    // 1100 || [a_sk]_252 =
    // 0xCFF0000000000000000000000000000000000000000000000000000000000000
    // 0^256 =
    // 0x0000000000000000000000000000000000000000000000000000000000000000
    // a_pk = blake2s( 1100 || [a_sk]_252 || 0^256)
    // Generated directly from a_sk and hashlib blake2s
    bits256 a_pk_bits256 = get_bits256_from_hexadecimal_str(
        "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49");

    // Get nf from a_sk and rho (PRF)
    //
    // nf = blake2s( 1110 || [a_sk]_252 || rho)
    // 1110 || [a_sk]_252 =
    // 0xEFF0000000000000000000000000000000000000000000000000000000000000
    // rho = FFFF000000000000000000000000000000000000000000000000000000009009
    // The test vector generated directly from a_sk and hashlib blake2s, gives:
    bits256 nf_bits256 = get_bits256_from_hexadecimal_str(
        "ff2f41920346251f6e7c67062149f98bc90c915d3d3020927ca01deab5da0fd7");

    // Get the coin's commitment (COMM)
    //
    // cm = blake2s(r || a_pk || rho || value_v)
    // Converted from old hex string
    // "e672300b3f422966e7cf8ea77e38ef0da595f3933eaf2d698a9859eb3bf674aa"
    // (big-endian)
    FieldT cm_field = FieldT("1042337073265819561558789652115525918926201435246"
                             "16864409706009242461667751082");

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
    zeth_note note(a_pk_bits256, value_bits64, rho_bits256, trap_r_bits256);

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
    bits256 trap_r_bits256 = get_bits256_from_hexadecimal_str(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF");
    bits64 value_bits64 = get_bits64_from_hexadecimal_str("2F0000000000000F");
    bits256 rho_bits256 = get_bits256_from_hexadecimal_str(
        "FFFF000000000000000000000000000000000000000000000000000000009009");
    bits256 a_pk_bits256 = get_bits256_from_hexadecimal_str(
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b");

    // Get the coin's commitment (COMM)
    //
    // cm = blake2s(r || a_pk || rho || value_v)
    FieldT cm = FieldT("9406909043221549055272426494996854870843153378267758164"
                       "1552564308222111558638");
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

    libsnark::pb_variable<FieldT> commitment;
    commitment.allocate(pb, " commitment");

    std::shared_ptr<output_note_gadget<FieldT, HashT>> output_note_g =
        std::shared_ptr<output_note_gadget<FieldT, HashT>>(
            new output_note_gadget<FieldT, HashT>(pb, rho_digest, commitment));

    // Create a note from the coin's data
    zeth_note note(a_pk_bits256, value_bits64, rho_bits256, trap_r_bits256);

    output_note_g->generate_r1cs_constraints();
    output_note_g->generate_r1cs_witness(note);
    libff::leave_block(
        "Data conversion to generate a witness of the note gadget", true);

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "************* SAT result: " << is_valid_witness
              << " ******************" << std::endl;
    ASSERT_TRUE(is_valid_witness);

    // Last check to make sure the commitment computed is the expected one
    ASSERT_EQ(pb.val(commitment), cm);
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
