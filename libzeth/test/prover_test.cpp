// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "gtest/gtest.h"
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

// Header to use the merkle tree data structure to keep a local merkle tree
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Have access to a chrono to measure the rough time of execution of a set of
// instructions
#include "libzeth/snarks_alias.hpp"

#include <chrono>
// Import only the core components of the SNARK (not the API components)
#include "libzeth/circuit_wrapper.hpp"
#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/libsnark_helpers/libsnark_helpers.hpp"
#include "libzeth/snarks_core_imports.hpp"
#include "libzeth/util.hpp"

using namespace libzeth;

// Instantiation of the templates for the tests
typedef libff::default_ec_pp ppT;

// Should be alt_bn128 in the CMakeLists.txt
typedef libff::Fr<ppT> FieldT;
typedef BLAKE2s_256<FieldT> HashT;
typedef MiMC_mp_gadget<FieldT> HashTreeT;
static const size_t TreeDepth = 4;

namespace
{

bool TestValidJS2In2Case1(
    circuit_wrapper<FieldT, HashT, HashTreeT, ppT, 2, 2, TreeDepth> &prover,
    libzeth::keyPairT<ppT> keypair)
{
    // --- General setup for the tests --- //
    libff::print_header(
        "test JS 2-2: IN => vpub_in = 0x0, note0 = 0x2F0000000000000F, note1 = "
        "0x0 || OUT => vpub_out = 0x1700000000000007, note0 = "
        "0x1800000000000008, note1 = 0x0");

    libff::enter_block("Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    // Note: `make_unique` should be C++14 compliant, but here we use c++11, so
    // we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>> test_merkle_tree =
        std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>>(
            new merkle_tree_field<FieldT, HashTreeT>(TreeDepth));
    libff::leave_block("Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1
    // -- //
    libff::enter_block("Create joinsplit_input", true);
    // Create the zeth note data for the commitment we will insert in the tree
    // (commitment to spend in this test)
    bits256 trap_r_bits256 = get_bits256_from_vector(hex_to_binary_vector(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"));
    bits64 value_bits64 =
        get_bits64_from_vector(hex_to_binary_vector("2F0000000000000F"));
    bits256 a_sk_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "FF0000000000000000000000000000000000000000000000000000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "FFFF000000000000000000000000000000000000000000000000000000009009"));
    bits256 a_pk_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49"));
    bits256 nf_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "ff2f41920346251f6e7c67062149f98bc90c915d3d3020927ca01deab5da0fd7"));
    FieldT cm_field = FieldT("1042337073265819561558789652115525918926201435246"
                             "16864409706009242461667751082");
    const size_t address_commitment = 1;
    libff::bit_vector address_bits;
    for (size_t i = 0; i < TreeDepth; ++i) {
        address_bits.push_back((address_commitment >> i) & 0x1);
    }
    bits256 h_sig = get_bits256_from_vector(hex_digest_to_binary_vector(
        "6838aac4d8247655715d3dfb9b32573da2b7d3360ba89ccdaaa7923bb24c99f7"));
    bits256 phi = get_bits256_from_vector(hex_digest_to_binary_vector(
        "403794c0e20e3bf36b820d8f7aef5505e5d1c7ac265d5efbcc3030a74a3f701b"));

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm_field);
    FieldT updated_root_value = test_merkle_tree->get_root();
    std::vector<FieldT> path = test_merkle_tree->get_path(address_commitment);

    // JS Inputs: 1 note of value > 0 to spend, and a dummy note
    zeth_note note_input(
        a_pk_bits256, value_bits64, rho_bits256, trap_r_bits256);
    zeth_note note_dummy_input(
        a_pk_bits256,
        hex_value_to_bits64("0000000000000000"),
        hex_digest_to_bits256(
            "AAAA00000000000000000000000000000000000000000000000000000000EEE"
            "E"),
        trap_r_bits256);
    joinsplit_input<FieldT, TreeDepth> input(
        path,
        get_bits_addr_from_vector<TreeDepth>(address_bits),
        note_input,
        a_sk_bits256,
        nf_bits256);
    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path
    // check Doesn't count in such case
    joinsplit_input<FieldT, TreeDepth> input_dummy(
        path,
        get_bits_addr_from_vector<TreeDepth>(address_bits),
        note_dummy_input,
        a_sk_bits256,
        nf_bits256);
    std::array<joinsplit_input<FieldT, TreeDepth>, 2> inputs;
    inputs[0] = input;
    inputs[1] = input_dummy;
    libff::leave_block("Create joinsplit_input", true);

    libff::enter_block("Create JSOutput/zeth_note", true);
    bits64 value_out_bits64 = hex_value_to_bits64("1800000000000008");
    bits256 a_pk_out_bits256 = hex_digest_to_bits256(
        "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b");
    bits256 rho_out_bits256;
    bits256 trap_r_out_bits256 = hex_digest_to_bits256(
        "11000000000000990000000000000099000000000000007700000000000000FF");

    zeth_note note_output(
        a_pk_out_bits256,
        value_out_bits64,
        rho_out_bits256,
        trap_r_out_bits256);
    zeth_note note_dummy_output(
        a_pk_out_bits256,
        hex_value_to_bits64("0000000000000000"),
        rho_out_bits256,
        trap_r_out_bits384);
    bits64 value_pub_out_bits64 = hex_value_to_bits64("1700000000000007");
    std::array<zeth_note, 2> outputs;
    outputs[0] = note_output;
    outputs[1] = note_dummy_output;
    libff::leave_block("Create JSOutput/zeth_note", true);

    libff::enter_block("Generate proof", true);
    extended_proof<ppT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        hex_value_to_bits64("0000000000000000"), // vpub_in = 0
        value_pub_out_bits64,
        h_sig,
        phi,
        keypair.pk);
    libff::leave_block("Generate proof", true);

    libff::enter_block("Verify proof", true);
    // Get the verification key
    libzeth::verificationKeyT<ppT> vk = keypair.vk;
    bool res = libzeth::verify(ext_proof, vk);
    std::cout << "Does the proof verify? " << res << std::endl;
    libff::leave_block("Verify proof", true);

    std::cout << "[DEBUG] Displaying the extended proof" << std::endl;
    ext_proof.dump_proof();
    std::cout << "[DEBUG] Displaying the primary inputs" << std::endl;
    ext_proof.dump_primary_inputs();

    return res;
}

bool TestValidJS2In2Case2(
    circuit_wrapper<FieldT, HashT, HashTreeT, ppT, 2, 2, TreeDepth> &prover,
    libzeth::keyPairT<ppT> keypair)
{
    libff::print_header(
        "Starting test: IN => v_pub = 0, note0 = 0x2F0000000000000F, note1 = "
        "0x0 || OUT => v_pub = 0x000000000000000B, note0 = 0x1A00000000000002, "
        "note1 = 0x1500000000000002");

    libff::enter_block("Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    // Note: `make_unique` should be C++14 compliant, but here we use c++11, so
    // we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>> test_merkle_tree =
        std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>>(
            new merkle_tree_field<FieldT, HashTreeT>(TreeDepth));
    libff::leave_block("Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1
    // -- //
    libff::enter_block("Create joinsplit_input", true);
    // Create the zeth note data for the commitment we will insert in the tree
    // (commitment to spend in this test)
    bits256 trap_r_bits256 = get_bits256_from_vector(hex_to_binary_vector(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"));
    bits64 value_bits64 =
        get_bits64_from_vector(hex_to_binary_vector("2F0000000000000F"));
    bits256 a_sk_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "FF0000000000000000000000000000000000000000000000000000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "FFFF000000000000000000000000000000000000000000000000000000009009"));
    bits256 a_pk_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49"));
    bits256 nf_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "ff2f41920346251f6e7c67062149f98bc90c915d3d3020927ca01deab5da0fd7"));
    FieldT cm_field = FieldT("1042337073265819561558789652115525918926201435246"
                             "16864409706009242461667751082");
    const size_t address_commitment = 1;
    libff::bit_vector address_bits;
    for (size_t i = 0; i < TreeDepth; ++i) {
        address_bits.push_back((address_commitment >> i) & 0x1);
    }
    bits256 h_sig = get_bits256_from_vector(hex_digest_to_binary_vector(
        "6838aac4d8247655715d3dfb9b32573da2b7d3360ba89ccdaaa7923bb24c99f7"));
    bits256 phi = get_bits256_from_vector(hex_digest_to_binary_vector(
        "403794c0e20e3bf36b820d8f7aef5505e5d1c7ac265d5efbcc3030a74a3f701b"));

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm_field);
    FieldT updated_root_value = test_merkle_tree->get_root();
    std::vector<FieldT> path = test_merkle_tree->get_path(address_commitment);

    // JS Inputs
    zeth_note note_input0(
        a_pk_bits256,
        value_bits64, // value associated with the commitment cm_field
        rho_bits256,
        trap_r_bits256);
    zeth_note note_input1(
        a_pk_bits256,
        hex_value_to_bits64("0000000000000000"),
        rho_bits256,
        trap_r_bits256);
    joinsplit_input<FieldT, TreeDepth> input0(
        path,
        get_bits_addr_from_vector<TreeDepth>(address_bits),
        note_input0,
        a_sk_bits256,
        nf_bits256);
    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path
    // check Doesn't count in such case
    joinsplit_input<FieldT, TreeDepth> input1(
        path,
        get_bits_addr_from_vector<TreeDepth>(address_bits),
        note_input1,
        a_sk_bits256,
        nf_bits256);
    std::array<joinsplit_input<FieldT, TreeDepth>, 2> inputs;
    inputs[0] = input0;
    inputs[1] = input1;
    libff::leave_block("Create joinsplit_input", true);

    libff::enter_block("Create JSOutput/zeth_note", true);
    bits256 a_pk_out_bits256 = hex_digest_to_bits256(
        "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b");
    bits256 rho_out_bits256;
    bits256 trap_r_out_bits256 = hex_digest_to_bits256(
        "11000000000000990000000000000099000000000000007700000000000000FF");
    zeth_note note_output0(
        a_pk_out_bits256,
        hex_value_to_bits64("1A00000000000002"),
        rho_out_bits256,
        trap_r_out_bits256);
    zeth_note note_output1(
        a_pk_out_bits256,
        hex_value_to_bits64("1500000000000002"),
        rho_out_bits256,
        trap_r_out_bits256);
    std::array<zeth_note, 2> outputs;
    outputs[0] = note_output0;
    outputs[1] = note_output1;
    libff::leave_block("Create JSOutput/zeth_note", true);

    libff::enter_block("Generate proof", true);
    // RHS = 0x1A00000000000002 + 0x1500000000000002 + 0x000000000000000B =
    // 2F0000000000000F (LHS)
    extended_proof<ppT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        // vpub_in = 0x0
        hex_value_to_bits64("0000000000000000"),
        // vpub_out = 0x000000000000000B
        hex_value_to_bits64("000000000000000B"),
        h_sig,
        phi,
        keypair.pk);
    libff::leave_block("Generate proof", true);

    libff::enter_block("Verify proof", true);
    // Get the verification key
    libzeth::verificationKeyT<ppT> vk = keypair.vk;
    bool res = libzeth::verify(ext_proof, vk);
    std::cout << "Does the proof verify? " << res << std::endl;
    libff::leave_block("Verify proof", true);

    std::cout << "[DEBUG] Displaying the extended proof" << std::endl;
    ext_proof.dump_proof();
    std::cout << "[DEBUG] Displaying the primary inputs" << std::endl;
    ext_proof.dump_primary_inputs();

    return res;
}

bool TestValidJS2In2Case3(
    circuit_wrapper<FieldT, HashT, HashTreeT, ppT, 2, 2, TreeDepth> &prover,
    libzeth::keyPairT<ppT> keypair)
{
    // --- General setup for the tests --- //
    libff::print_header(
        "Starting test: IN => v_pub = 0x0000000000000010, note0 = "
        "0x2F0000000000000F, note1 = 0x0 || OUT => v_pub = 0x000000000000000B, "
        "note0 = 0x1A00000000000012, note1 = 0x1500000000000002");

    libff::enter_block("Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    // Note: `make_unique` should be C++14 compliant, but here we use c++11, so
    // we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>> test_merkle_tree =
        std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>>(
            new merkle_tree_field<FieldT, HashTreeT>(TreeDepth));
    libff::leave_block("Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1
    // -- //
    libff::enter_block("Create joinsplit_input", true);
    // Create the zeth note data for the commitment we will insert in the tree
    // (commitment to spend in this test)
    bits256 trap_r_bits256 = get_bits256_from_vector(hex_to_binary_vector(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"));
    bits64 value_bits64 =
        get_bits64_from_vector(hex_to_binary_vector("2F0000000000000F"));
    bits256 a_sk_bits256 = get_bits256_from_vector(
        hex_digest_to_binary_vector("FF00000000000000000000000000000000"
                                    "00000000000000000000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(
        hex_digest_to_binary_vector("FFFF000000000000000000000000000000"
                                    "000000000000000000000000009009"));
    bits256 a_pk_bits256 = get_bits256_from_vector(
        hex_digest_to_binary_vector("f172d7299ac8ac974ea59413e4a8769182"
                                    "6df038ba24a2b52d5c5d15c2cc8c49"));
    bits256 nf_bits256 = get_bits256_from_vector(
        hex_digest_to_binary_vector("ff2f41920346251f6e7c67062149f98bc9"
                                    "0c915d3d3020927ca01deab5da0fd7"));
    FieldT cm_field = FieldT("1042337073265819561558789652115525918926201435246"
                             "16864409706009242461667751082");
    const size_t address_commitment = 1;
    libff::bit_vector address_bits;
    for (size_t i = 0; i < TreeDepth; ++i) {
        address_bits.push_back((address_commitment >> i) & 0x1);
    }
    bits256 h_sig = get_bits256_from_vector(hex_digest_to_binary_vector(
        "6838aac4d8247655715d3dfb9b32573da2b7d3360ba89ccdaaa7923bb24c99f7"));
    bits256 phi = get_bits256_from_vector(hex_digest_to_binary_vector(
        "403794c0e20e3bf36b820d8f7aef5505e5d1c7ac265d5efbcc3030a74a3f701b"));

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm_field);
    FieldT updated_root_value = test_merkle_tree->get_root();
    std::vector<FieldT> path = test_merkle_tree->get_path(address_commitment);

    // JS Inputs
    zeth_note note_input0(
        a_pk_bits256,
        value_bits64, // value associated with the commitment cm_field
        rho_bits256,
        trap_r_bits256);
    zeth_note note_input1(
        a_pk_bits256,
        hex_value_to_bits64("0000000000000000"),
        rho_bits256,
        trap_r_bits256);
    joinsplit_input<FieldT, TreeDepth> input0(
        path,
        get_bits_addr_from_vector<TreeDepth>(address_bits),
        note_input0,
        a_sk_bits256,
        nf_bits256);
    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path
    // check Doesn't count in such case
    joinsplit_input<FieldT, TreeDepth> input1(
        path,
        get_bits_addr_from_vector<TreeDepth>(address_bits),
        note_input1,
        a_sk_bits256,
        nf_bits256);
    std::array<joinsplit_input<FieldT, TreeDepth>, 2> inputs;
    inputs[0] = input0;
    inputs[1] = input1;
    libff::leave_block("Create joinsplit_input", true);

    libff::enter_block("Create JSOutput/zeth_note", true);
    bits256 a_pk_out_bits256 = hex_digest_to_bits256(
        "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b");
    bits256 rho_out_bits256;
    bits256 trap_r_out_bits256 = hex_digest_to_bits256(
        "11000000000000990000000000000099000000000000007700000000000000FF");

    zeth_note note_output0(
        a_pk_out_bits256,
        hex_value_to_bits64("1A00000000000012"),
        rho_out_bits256,
        trap_r_out_bits256);
    zeth_note note_output1(
        a_pk_out_bits256,
        hex_value_to_bits64("1500000000000002"),
        rho_out_bits256,
        trap_r_out_bits256);
    std::array<zeth_note, 2> outputs;
    outputs[0] = note_output0;
    outputs[1] = note_output1;
    libff::leave_block("Create JSOutput/zeth_note", true);

    libff::enter_block("Generate proof", true);
    // (RHS) 0x1A00000000000012 + 0x1500000000000002 + 0x000000000000000B =
    // 2F0000000000000F + 0x0000000000000010 + 0x0 (LHS)
    extended_proof<ppT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        hex_value_to_bits64(
            "0000000000000010"), // v_pub_in = 0x0000000000000010
        hex_value_to_bits64(
            "000000000000000B"), // v_pub_out = 0x000000000000000B
        h_sig,
        phi,
        keypair.pk);
    libff::leave_block("Generate proof", true);

    libff::enter_block("Verify proof", true);
    // Get the verification key
    libzeth::verificationKeyT<ppT> vk = keypair.vk;
    bool res = libzeth::verify(ext_proof, vk);
    std::cout << "Does the proof verfy? " << res << std::endl;
    libff::leave_block("Verify proof", true);

    std::cout << "[DEBUG] Displaying the extended proof" << std::endl;
    ext_proof.dump_proof();
    std::cout << "[DEBUG] Displaying the primary inputs" << std::endl;
    ext_proof.dump_primary_inputs();

    return res;
}

bool TestValidJS2In2Deposit(
    circuit_wrapper<FieldT, HashT, HashTreeT, ppT, 2, 2, TreeDepth> &prover,
    libzeth::keyPairT<ppT> keypair)
{
    // --- General setup for the tests --- //
    libff::print_header("Starting test: IN => v_pub = 0x6124FEE993BC0000, "
                        "note0 = 0x0, note1 = 0x0 || OUT => v_pub = 0x0, note0 "
                        "= 0x3782DACE9D900000, note1 = 0x29A2241AF62C0000");

    libff::enter_block("Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    // Note: `make_unique` should be C++14 compliant, but here we use c++11, so
    // we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>> test_merkle_tree =
        std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>>(
            new merkle_tree_field<FieldT, HashTreeT>(TreeDepth));
    libff::leave_block("Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1
    // -- //
    libff::enter_block("Create joinsplit_input", true);
    // Create the zeth note data for the commitment we will insert in the tree
    // (commitment to spend in this test)
    bits256 trap_r_bits256 = get_bits256_from_vector(hex_to_binary_vector(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"));
    bits256 a_sk_bits256 = get_bits256_from_vector(
        hex_digest_to_binary_vector("FF00000000000000000000000000000000"
                                    "00000000000000000000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(
        hex_digest_to_binary_vector("FFFF000000000000000000000000000000"
                                    "000000000000000000000000009009"));
    bits256 a_pk_bits256 = get_bits256_from_vector(
        hex_digest_to_binary_vector("f172d7299ac8ac974ea59413e4a8769182"
                                    "6df038ba24a2b52d5c5d15c2cc8c49"));
    bits256 nf_bits256 = get_bits256_from_vector(
        hex_digest_to_binary_vector("ff2f41920346251f6e7c67062149f98bc9"
                                    "0c915d3d3020927ca01deab5da0fd7"));
    FieldT cm_field = FieldT("8049045390937310931330301778888084231593485252743"
                             "182393007013989361193264682");

    const size_t address_commitment = 1;
    libff::bit_vector address_bits;
    for (size_t i = 0; i < TreeDepth; ++i) {
        address_bits.push_back((address_commitment >> i) & 0x1);
    }
    bits256 h_sig = get_bits256_from_vector(hex_digest_to_binary_vector(
        "6838aac4d8247655715d3dfb9b32573da2b7d3360ba89ccdaaa7923bb24c99f7"));
    bits256 phi = get_bits256_from_vector(hex_digest_to_binary_vector(
        "403794c0e20e3bf36b820d8f7aef5505e5d1c7ac265d5efbcc3030a74a3f701b"));

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm_field);
    FieldT updated_root_value = test_merkle_tree->get_root();
    std::vector<FieldT> path = test_merkle_tree->get_path(address_commitment);

    // JS Inputs
    zeth_note note_input0(
        a_pk_bits256,
        hex_value_to_bits64("0000000000000000"),
        rho_bits256,
        trap_r_bits256);
    zeth_note note_input1(
        a_pk_bits256,
        hex_value_to_bits64("0000000000000000"),
        rho_bits256,
        trap_r_bits256);
    joinsplit_input<FieldT, TreeDepth> input0(
        path,
        get_bits_addr_from_vector<TreeDepth>(address_bits),
        note_input0,
        a_sk_bits256,
        nf_bits256);
    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path
    // check Doesn't count in such case
    joinsplit_input<FieldT, TreeDepth> input1(
        path,
        get_bits_addr_from_vector<TreeDepth>(address_bits),
        note_input1,
        a_sk_bits256,
        nf_bits256);
    std::array<joinsplit_input<FieldT, TreeDepth>, 2> inputs;
    inputs[0] = input0;
    inputs[1] = input1;
    libff::leave_block("Create joinsplit_input", true);

    libff::enter_block("Create JSOutput/zeth_note", true);
    bits256 a_pk_out_bits256 = hex_digest_to_bits256(
        "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b");
    bits256 rho_out_bits256;
    bits256 trap_r_out_bits256 = hex_digest_to_bits256(
        "11000000000000990000000000000099000000000000007700000000000000FF");
    zeth_note note_output0(
        a_pk_out_bits256,
        hex_value_to_bits64("3782DACE9D900000"),
        rho_out_bits256,
        trap_r_out_bits256);
    zeth_note note_output1(
        a_pk_out_bits256,
        hex_value_to_bits64("29A2241AF62C0000"),
        rho_out_bits256,
        trap_r_out_bits256);
    std::array<zeth_note, 2> outputs;
    outputs[0] = note_output0;
    outputs[1] = note_output1;
    libff::leave_block("Create JSOutput/zeth_note", true);

    libff::enter_block("Generate proof", true);
    // RHS = 0x0 + 0x3782DACE9D900000 + 0x29A2241AF62C0000 = 0x6124FEE993BC0000
    // (LHS)
    extended_proof<ppT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        // v_pub_in = 0x6124FEE993BC0000
        hex_value_to_bits64("6124FEE993BC0000"),
        // v_pub_out = 0x000000000000000B
        hex_value_to_bits64("0000000000000000"),
        h_sig,
        phi,
        keypair.pk);
    libff::leave_block("Generate proof", true);

    libff::enter_block("Verify proof", true);
    // Get the verification key
    libzeth::verificationKeyT<ppT> vk = keypair.vk;
    bool res = libzeth::verify(ext_proof, vk);

    ext_proof.dump_primary_inputs();
    std::cout << "Does the proof verify? " << res << std::endl;
    libff::leave_block("Verify proof", true);

    std::cout << "[DEBUG] Displaying the extended proof" << std::endl;
    ext_proof.dump_proof();
    std::cout << "[DEBUG] Displaying the primary inputs" << std::endl;
    ext_proof.dump_primary_inputs();

    return res;
}

bool TestInvalidJS2In2(
    circuit_wrapper<FieldT, HashT, HashTreeT, ppT, 2, 2, TreeDepth> &prover,
    libzeth::keyPairT<ppT> keypair)
{
    // --- General setup for the tests --- //
    libff::print_header("Starting test: IN => v_pub = 0xFA80001400000000, "
                        "note0 = 0x0, note1 = 0x0 || OUT => v_pub = 0x0, note0 "
                        "= 0x8530000A00000001, note1 = 0x7550000A00000000");

    libff::enter_block("Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    // Note: `make_unique` should be C++14 compliant, but here we use c++11, so
    // we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>> test_merkle_tree =
        std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>>(
            new merkle_tree_field<FieldT, HashTreeT>(TreeDepth));
    libff::leave_block("Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1
    // -- //
    libff::enter_block("Create joinsplit_input", true);
    // Create the zeth note data for the commitment we will insert in the tree
    // (commitment to spend in this test)
    bits256 trap_r_bits256 = get_bits256_from_vector(hex_to_binary_vector(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"));
    bits256 a_sk_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "FF0000000000000000000000000000000000000000000000000000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "FFFF000000000000000000000000000000000000000000000000000000009009"));
    bits256 a_pk_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49"));
    bits256 nf_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "ff2f41920346251f6e7c67062149f98bc90c915d3d3020927ca01deab5da0fd7"));
    FieldT cm_field = FieldT("8049045390937310931330301778888084231593485252743"
                             "182393007013989361193264682");

    const size_t address_commitment = 1;
    libff::bit_vector address_bits;
    for (size_t i = 0; i < TreeDepth; ++i) {
        address_bits.push_back((address_commitment >> i) & 0x1);
    }
    bits256 h_sig = get_bits256_from_vector(hex_digest_to_binary_vector(
        "6838aac4d8247655715d3dfb9b32573da2b7d3360ba89ccdaaa7923bb24c99f7"));
    bits256 phi = get_bits256_from_vector(hex_digest_to_binary_vector(
        "403794c0e20e3bf36b820d8f7aef5505e5d1c7ac265d5efbcc3030a74a3f701b"));

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm_field);
    FieldT updated_root_value = test_merkle_tree->get_root();
    std::vector<FieldT> path = test_merkle_tree->get_path(address_commitment);

    // JS Inputs
    zeth_note note_input0(
        a_pk_bits256,
        hex_value_to_bits64("0000000000000000"),
        rho_bits256,
        trap_r_bits256);
    zeth_note note_input1(
        a_pk_bits256,
        hex_value_to_bits64("0000000000000000"),
        rho_bits256,
        trap_r_bits256);
    joinsplit_input<FieldT, TreeDepth> input0(
        path,
        get_bits_addr_from_vector<TreeDepth>(address_bits),
        note_input0,
        a_sk_bits256,
        nf_bits256);
    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path
    // check Doesn't count in such case
    joinsplit_input<FieldT, TreeDepth> input1(
        path,
        get_bits_addr_from_vector<TreeDepth>(address_bits),
        note_input1,
        a_sk_bits256,
        nf_bits256);
    std::array<joinsplit_input<FieldT, TreeDepth>, 2> inputs;
    inputs[0] = input0;
    inputs[1] = input1;
    libff::leave_block("Create joinsplit_input", true);

    libff::enter_block("Create JSOutput/zeth_note", true);
    bits256 a_pk_out_bits256 = hex_digest_to_bits256(
        "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b");
    bits256 rho_out_bits256;
    bits256 trap_r_out_bits256 = hex_digest_to_bits256(
        "11000000000000990000000000000099000000000000007700000000000000FF");

    // 0x8530000A00000000 = 9.597170848876199937 ETH
    zeth_note note_output0(
        a_pk_out_bits256,
        hex_value_to_bits64("8530000A00000001"),
        rho_out_bits256,
        trap_r_out_bits256);
    // 0x7550000A00000000 = 8.453256543524093952 ETH
    zeth_note note_output1(
        a_pk_out_bits256,
        hex_value_to_bits64("7550000A00000000"),
        rho_out_bits256,
        trap_r_out_bits256);
    std::array<zeth_note, 2> outputs;
    outputs[0] = note_output0;
    outputs[1] = note_output1;
    libff::leave_block("Create JSOutput/zeth_note", true);

    libff::enter_block("Generate proof", true);
    // LHS = 0xFA80001400000000 (18.050427392400293888 ETH) =/=
    // 0x8530000A00000001 (9.597170848876199937 ETH) + 0x7550000A00000000
    // (8.453256543524093952 ETH) = RHS LHS = 18.050427392400293888 ETH RHS
    // = 18.050427392400293889 ETH (1 wei higher than LHS)
    extended_proof<ppT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        // vpub_in = 0xFA80001400000000 = 18.050427392400293888 ETH
        hex_value_to_bits64("FA80001400000000"),
        // vpub_out = 0x0
        hex_value_to_bits64("0000000000000000"),
        h_sig,
        phi,
        keypair.pk);
    libff::leave_block("Generate proof", true);

    libff::enter_block("Verify proof", true);
    // Get the verification key
    libzeth::verificationKeyT<ppT> vk = keypair.vk;
    bool res = libzeth::verify(ext_proof, vk);
    std::cout << "Does the proof verify ? " << res << std::endl;
    libff::leave_block("Verify proof", true);

    std::cout << "[DEBUG] Displaying the extended proof" << std::endl;
    ext_proof.dump_proof();
    std::cout << "[DEBUG] Displaying the primary inputs" << std::endl;
    ext_proof.dump_primary_inputs();

    return res;
}

TEST(MainTests, ProofGenAndVerifJS2to2)
{
    // Run the trusted setup once for all tests, and keep the keypair in memory
    // for the duration of the tests
    circuit_wrapper<FieldT, HashT, HashTreeT, ppT, 2, 2, TreeDepth>
        proverJS2to2;

    libzeth::keyPairT<ppT> keypair = proverJS2to2.generate_trusted_setup();
    bool res = false;

    res = TestValidJS2In2Case1(proverJS2to2, keypair);
    ASSERT_TRUE(res);

    res = TestValidJS2In2Case2(proverJS2to2, keypair);
    ASSERT_TRUE(res);

    res = TestValidJS2In2Case3(proverJS2to2, keypair);
    ASSERT_TRUE(res);

    res = TestValidJS2In2Deposit(proverJS2to2, keypair);
    ASSERT_TRUE(res);

    // The following test is expected to throw an exception because the LHS =/=
    // RHS
    try {
        res = TestInvalidJS2In2(proverJS2to2, keypair);
        ASSERT_TRUE(res);
    } catch (const std::invalid_argument &e) {
        std::cerr << "Invalid argument exception: " << e.what() << '\n';
    }
}

} // namespace

int main(int argc, char **argv)
{
    // /!\ WARNING: Do once for all tests. Do not
    // forget to do this !!!!
    ppT::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
