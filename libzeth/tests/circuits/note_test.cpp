// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/circuits/notes/note.hpp"
#include "libzeth/core/bits.hpp"
#include "libzeth/core/merkle_tree_field.hpp"
#include "libzeth/core/note.hpp"
#include "libzeth/core/utils.hpp"
#include "zeth_config.h"

#include <gtest/gtest.h>

using namespace libzeth;

// We use our hash functions to do the tests
using pp = defaults::pp;
using Field = defaults::Field;
using Hash = BLAKE2s_256<Field>;
using HashTree = MiMC_mp_gadget<Field, MiMC_permutation_gadget<Field, 7, 91>>;
static const size_t TreeDepth = 4;

namespace
{

TEST(TestNoteCircuits, TestInputNoteGadget)
{
    libsnark::protoboard<Field> pb;
    libsnark::pb_variable<Field> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = Field::zero();

    libff::enter_block(
        "Initialize the coins' data (nullifier, a_sk and a_pk, cm, rho)", true);
    bits256 trap_r_bits256 = bits256::from_hex(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF");
    bits64 value_bits64 = bits64::from_hex("2F0000000000000F");
    bits256 a_sk_bits256 = bits256::from_hex(
        "FF0000000000000000000000000000000000000000000000000000000000000F");
    bits256 rho_bits256 = bits256::from_hex(
        "FFFF000000000000000000000000000000000000000000000000000000009009");

    // Get a_pk from a_sk (PRF)
    //
    // 1100 || [a_sk]_252 =
    // 0xCFF0000000000000000000000000000000000000000000000000000000000000
    // 0^256 =
    // 0x0000000000000000000000000000000000000000000000000000000000000000
    // a_pk = blake2s( 1100 || [a_sk]_252 || 0^256)
    // Generated directly from a_sk and hashlib blake2s
    bits256 a_pk_bits256 = bits256::from_hex(
        "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49");

    // Get nf from a_sk and rho (PRF)
    //
    // nf = blake2s( 1110 || [a_sk]_252 || rho)
    // 1110 || [a_sk]_252 =
    // 0xEFF0000000000000000000000000000000000000000000000000000000000000
    // rho = FFFF000000000000000000000000000000000000000000000000000000009009
    // The test vector generated directly from a_sk and hashlib blake2s, gives:
    bits256 nf_bits256 = bits256::from_hex(
        "ff2f41920346251f6e7c67062149f98bc90c915d3d3020927ca01deab5da0fd7");

    // Get the coin's commitment (COMM)
    //
    // cm = blake2s(r || a_pk || rho || value_v)
    // Converted from old hex string
    // "e672300b3f422966e7cf8ea77e38ef0da595f3933eaf2d698a9859eb3bf674aa"
    // (big-endian)
    Field cm_field = Field("1042337073265819561558789652115525918926201435246"
                           "16864409706009242461667751082");

    libff::leave_block(
        "Initialize the coins' data (nullifier, a_sk and a_pk, cm, rho)", true);

    libff::enter_block(
        "Setup a local merkle tree and append our commitment to it", true);
    std::unique_ptr<merkle_tree_field<Field, HashTree>> test_merkle_tree =
        std::unique_ptr<merkle_tree_field<Field, HashTree>>(
            new merkle_tree_field<Field, HashTree>(TreeDepth));

    // In practice the address is emitted by the mixer contract once the
    // commitment is appended to the tree
    const size_t address_commitment = 1;
    bits_addr<TreeDepth> address_bits =
        bits_addr<TreeDepth>::from_size_t(address_commitment);

    test_merkle_tree->set_value(address_commitment, cm_field);

    // Get the root of the new/non-empty tree (after insertion)
    Field updated_root_value = test_merkle_tree->get_root();

    libff::leave_block(
        "Setup a local merkle tree and append our commitment to it", true);

    libff::enter_block(
        "Data conversion to generate a witness of the note gadget", true);

    std::shared_ptr<libsnark::digest_variable<Field>> a_sk_digest(
        new libsnark::digest_variable<Field>(
            pb, Hash::get_digest_len(), "a_sk_digest"));
    a_sk_digest->generate_r1cs_constraints();
    a_sk_digest->generate_r1cs_witness(
        libff::bit_vector(a_sk_bits256.to_vector()));

    std::shared_ptr<libsnark::digest_variable<Field>> nullifier_digest(
        new libsnark::digest_variable<Field>(
            pb, Hash::get_digest_len(), "nullifier_digest"));
    nullifier_digest->generate_r1cs_constraints();
    nullifier_digest->generate_r1cs_witness(
        libff::bit_vector(nf_bits256.to_vector()));

    libsnark::pb_variable<Field> merkle_root;
    merkle_root.allocate(pb, "root");
    pb.val(merkle_root) = updated_root_value;

    input_note_gadget<Field, Hash, HashTree, TreeDepth> input_note_g(
        pb, ZERO, a_sk_digest, nullifier_digest, merkle_root);

    // Get the merkle path to the commitment we appended
    std::vector<Field> path = test_merkle_tree->get_path(address_commitment);

    // Create a note from the coin's data
    zeth_note note(a_pk_bits256, value_bits64, rho_bits256, trap_r_bits256);

    input_note_g.generate_r1cs_constraints();
    input_note_g.generate_r1cs_witness(path, address_bits, note);
    libff::leave_block(
        "Data conversion to generate a witness of the note gadget", true);

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "************* SAT result: " << is_valid_witness
              << " ******************" << std::endl;

    ASSERT_TRUE(is_valid_witness);
}

TEST(TestNoteCircuits, TestOutputNoteGadget)
{
    libsnark::protoboard<Field> pb;
    libsnark::pb_variable<Field> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = Field::zero();

    libff::enter_block(
        "Initialize the output coins' data (a_pk, cm, rho)", true);
    bits256 trap_r_bits256 = bits256::from_hex(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF");
    bits64 value_bits64 = bits64::from_hex("2F0000000000000F");
    bits256 rho_bits256 = bits256::from_hex(
        "FFFF000000000000000000000000000000000000000000000000000000009009");
    bits256 a_pk_bits256 = bits256::from_hex(
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b");

    // Get the coin's commitment (COMM)
    //
    // cm = blake2s(r || a_pk || rho || value_v)
    Field cm = Field("9406909043221549055272426494996854870843153378267758164"
                     "1552564308222111558638");
    libff::leave_block(
        "Initialize the output coins' data (a_pk, cm, rho)", true);

    libff::enter_block(
        "Data conversion to generate a witness of the note gadget", true);
    std::shared_ptr<libsnark::digest_variable<Field>> rho_digest(
        new libsnark::digest_variable<Field>(
            pb, Hash::get_digest_len(), "rho_digest"));
    rho_digest->generate_r1cs_constraints();
    rho_digest->generate_r1cs_witness(rho_bits256.to_vector());

    libsnark::pb_variable<Field> commitment;
    commitment.allocate(pb, " commitment");

    std::shared_ptr<output_note_gadget<Field, Hash>> output_note_g =
        std::shared_ptr<output_note_gadget<Field, Hash>>(
            new output_note_gadget<Field, Hash>(pb, rho_digest, commitment));

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
}

} // namespace

int main(int argc, char **argv)
{
    // /!\ WARNING: Do once for all tests. Do not
    // forget to do this !!!!
    pp::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
