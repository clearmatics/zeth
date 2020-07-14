// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/circuit_wrapper.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/snarks/groth16/groth16_snark.hpp"
#include "libzeth/snarks/pghr13/pghr13_snark.hpp"
#include "zeth_config.h"

#include <chrono>
#include <gtest/gtest.h>
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Use the default ppT and other options from the circuit code, but force the
// Merkle tree depth to 4. Parameterize the test code on the snark, so that
// this code can test all available snark schemes, indepedent of the build
// configuration.

static const size_t TreeDepth = 4;

using namespace libzeth;

template<typename snarkT>
using prover = circuit_wrapper<
    HashT<FieldT>,
    HashTreeT<FieldT>,
    ppT,
    snarkT,
    2,
    2,
    TreeDepth>;

namespace
{

const bits256 zero_bits256 = bits256::from_hex(
    "0000000000000000000000000000000000000000000000000000000000000000");

template<typename snarkT>
bool TestValidJS2In2Case1(
    const prover<snarkT> &prover, const typename snarkT::KeypairT &keypair)
{
    // --- General setup for the tests --- //
    libff::print_header(
        "test JS 2-2:\n"
        " IN => vpub_in=0x0, note0=0x2F0000000000000F, note1=0x0\n"
        " OUT=> vpub_out=0x1700000000000007, note0=0x1800000000000008, "
        "note1=0x0");

    libff::enter_block("Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    merkle_tree_field<FieldT, HashTreeT<FieldT>> test_merkle_tree(TreeDepth);
    libff::leave_block("Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1
    // -- //
    libff::enter_block("Create joinsplit_input", true);
    // Create the zeth note data for the commitment we will insert in the tree
    // (commitment to spend in this test)
    bits256 trap_r_bits256 = bits256::from_hex(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF");
    bits64 value_bits64 = bits64::from_hex("2F0000000000000F");
    bits256 a_sk_bits256 = bits256::from_hex(
        "FF0000000000000000000000000000000000000000000000000000000000000F");
    bits256 rho_bits256 = bits256::from_hex(
        "FFFF000000000000000000000000000000000000000000000000000000009009");
    bits256 a_pk_bits256 = bits256::from_hex(
        "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49");
    bits256 nf_bits256 = bits256::from_hex(
        "ff2f41920346251f6e7c67062149f98bc90c915d3d3020927ca01deab5da0fd7");
    FieldT cm_field = FieldT("1042337073265819561558789652115525918926201435246"
                             "16864409706009242461667751082");
    const size_t address_commitment = 1;
    libff::bit_vector address_bits;
    for (size_t i = 0; i < TreeDepth; ++i) {
        address_bits.push_back((address_commitment >> i) & 0x1);
    }
    bits256 h_sig = bits256::from_hex(
        "6838aac4d8247655715d3dfb9b32573da2b7d3360ba89ccdaaa7923bb24c99f7");
    bits256 phi = bits256::from_hex(
        "403794c0e20e3bf36b820d8f7aef5505e5d1c7ac265d5efbcc3030a74a3f701b");

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree.set_value(address_commitment, cm_field);
    FieldT updated_root_value = test_merkle_tree.get_root();
    std::vector<FieldT> path = test_merkle_tree.get_path(address_commitment);

    // JS Inputs: 1 note of value > 0 to spend, and a dummy note
    std::array<joinsplit_input<FieldT, TreeDepth>, 2> inputs;

    inputs[0] = joinsplit_input<FieldT, TreeDepth>(
        std::vector<FieldT>(path),
        bits_addr<TreeDepth>::from_vector(address_bits),
        zeth_note(a_pk_bits256, value_bits64, rho_bits256, trap_r_bits256),
        bits256(a_sk_bits256),
        bits256(nf_bits256));
    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path
    // check Doesn't count in such case
    zeth_note note_dummy_input(
        a_pk_bits256,
        bits64::from_hex("0000000000000000"),
        bits256::from_hex(
            "AAAA00000000000000000000000000000000000000000000000000000000EEEE"),
        trap_r_bits256);
    inputs[1] = joinsplit_input<FieldT, TreeDepth>(
        std::move(path),
        bits_addr<TreeDepth>::from_vector(address_bits),
        note_dummy_input,
        a_sk_bits256,
        nf_bits256);
    libff::leave_block("Create joinsplit_input", true);

    libff::enter_block("Create JSOutput/zeth_note", true);
    bits64 value_out_bits64 = bits64::from_hex("1800000000000008");
    bits256 a_pk_out_bits256 = bits256::from_hex(
        "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b");
    const bits256 &rho_out_bits256 = zero_bits256;
    bits256 trap_r_out_bits256 = bits256::from_hex(
        "11000000000000990000000000000099000000000000007700000000000000FF");
    zeth_note note_output(
        a_pk_out_bits256,
        value_out_bits64,
        rho_out_bits256,
        trap_r_out_bits256);
    zeth_note note_dummy_output(
        a_pk_out_bits256,
        bits64::from_hex("0000000000000000"),
        rho_out_bits256,
        trap_r_out_bits256);
    bits64 value_pub_out_bits64 = bits64::from_hex("1700000000000007");
    std::array<zeth_note, 2> outputs;
    outputs[0] = note_output;
    outputs[1] = note_dummy_output;
    libff::leave_block("Create JSOutput/zeth_note", true);

    libff::enter_block("Generate proof", true);
    extended_proof<ppT, snarkT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        bits64::from_hex("0000000000000000"), // vpub_in = 0
        value_pub_out_bits64,
        h_sig,
        phi,
        keypair.pk);
    libff::leave_block("Generate proof", true);

    libff::enter_block("Verify proof", true);
    // Get the verification key
    typename snarkT::VerificationKeyT vk = keypair.vk;
    bool res = snarkT::verify(
        ext_proof.get_primary_inputs(), ext_proof.get_proof(), vk);
    std::cout << "Does the proof verify? " << res << std::endl;
    libff::leave_block("Verify proof", true);

    std::cout << "[DEBUG] Displaying the extended proof" << std::endl;
    ext_proof.write_json(std::cout);

    return res;
}

template<typename snarkT>
bool TestValidJS2In2Case2(
    const prover<snarkT> &prover, const typename snarkT::KeypairT &keypair)
{
    libff::print_header(
        "Starting test:\n"
        " IN => v_pub=0, note0=0x2F0000000000000F, note1=0x0\n"
        " OUT=> v_pub=0x000000000000000B, note0=0x1A00000000000002,"
        " note1=0x1500000000000002");

    libff::enter_block("Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    merkle_tree_field<FieldT, HashTreeT<FieldT>> test_merkle_tree(TreeDepth);
    libff::leave_block("Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1
    // -- //
    libff::enter_block("Create joinsplit_input", true);
    // Create the zeth note data for the commitment we will insert in the tree
    // (commitment to spend in this test)
    bits256 trap_r_bits256 = bits256::from_hex(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF");
    bits64 value_bits64 = bits64::from_hex("2F0000000000000F");
    bits256 a_sk_bits256 = bits256::from_hex(
        "FF0000000000000000000000000000000000000000000000000000000000000F");
    bits256 rho_bits256 = bits256::from_hex(
        "FFFF000000000000000000000000000000000000000000000000000000009009");
    bits256 a_pk_bits256 = bits256::from_hex(
        "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49");
    bits256 nf_bits256 = bits256::from_hex(
        "ff2f41920346251f6e7c67062149f98bc90c915d3d3020927ca01deab5da0fd7");
    FieldT cm_field = FieldT("1042337073265819561558789652115525918926201435246"
                             "16864409706009242461667751082");
    const size_t address_commitment = 1;
    libff::bit_vector address_bits;
    for (size_t i = 0; i < TreeDepth; ++i) {
        address_bits.push_back((address_commitment >> i) & 0x1);
    }
    bits256 h_sig = bits256::from_hex(
        "6838aac4d8247655715d3dfb9b32573da2b7d3360ba89ccdaaa7923bb24c99f7");
    bits256 phi = bits256::from_hex(
        "403794c0e20e3bf36b820d8f7aef5505e5d1c7ac265d5efbcc3030a74a3f701b");

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree.set_value(address_commitment, cm_field);
    FieldT updated_root_value = test_merkle_tree.get_root();
    std::vector<FieldT> path = test_merkle_tree.get_path(address_commitment);

    // JS Inputs
    std::array<joinsplit_input<FieldT, TreeDepth>, 2> inputs;
    inputs[0] = joinsplit_input<FieldT, TreeDepth>(
        std::vector<FieldT>(path),
        bits_addr<TreeDepth>::from_vector(address_bits),
        zeth_note(a_pk_bits256, value_bits64, rho_bits256, trap_r_bits256),
        bits256(a_sk_bits256),
        bits256(nf_bits256));
    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path
    // check Doesn't count in such case
    zeth_note note_input1(
        a_pk_bits256,
        bits64::from_hex("0000000000000000"),
        rho_bits256,
        trap_r_bits256);
    inputs[1] = joinsplit_input<FieldT, TreeDepth>(
        std::move(path),
        bits_addr<TreeDepth>::from_vector(address_bits),
        note_input1,
        a_sk_bits256,
        nf_bits256);
    libff::leave_block("Create joinsplit_input", true);

    libff::enter_block("Create JSOutput/zeth_note", true);
    bits256 a_pk_out_bits256 = bits256::from_hex(
        "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b");
    const bits256 &rho_out_bits256 = zero_bits256;
    bits256 trap_r_out_bits256 = bits256::from_hex(
        "11000000000000990000000000000099000000000000007700000000000000FF");
    zeth_note note_output0(
        a_pk_out_bits256,
        bits64::from_hex("1A00000000000002"),
        rho_out_bits256,
        trap_r_out_bits256);
    zeth_note note_output1(
        a_pk_out_bits256,
        bits64::from_hex("1500000000000002"),
        rho_out_bits256,
        trap_r_out_bits256);
    std::array<zeth_note, 2> outputs;
    outputs[0] = note_output0;
    outputs[1] = note_output1;
    libff::leave_block("Create JSOutput/zeth_note", true);

    libff::enter_block("Generate proof", true);
    // RHS = 0x1A00000000000002 + 0x1500000000000002 + 0x000000000000000B =
    // 2F0000000000000F (LHS)
    extended_proof<ppT, snarkT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        // vpub_in = 0x0
        bits64::from_hex("0000000000000000"),
        // vpub_out = 0x000000000000000B
        bits64::from_hex("000000000000000B"),
        h_sig,
        phi,
        keypair.pk);
    libff::leave_block("Generate proof", true);

    libff::enter_block("Verify proof", true);
    // Get the verification key
    typename snarkT::VerificationKeyT vk = keypair.vk;
    bool res = snarkT::verify(
        ext_proof.get_primary_inputs(), ext_proof.get_proof(), vk);
    std::cout << "Does the proof verify? " << res << std::endl;
    libff::leave_block("Verify proof", true);

    std::cout << "[DEBUG] Displaying the extended proof" << std::endl;
    ext_proof.write_json(std::cout);

    return res;
}

template<typename snarkT>
bool TestValidJS2In2Case3(
    const prover<snarkT> &prover, const typename snarkT::KeypairT &keypair)
{
    // --- General setup for the tests --- //
    libff::print_header(
        "Starting test:\n"
        " IN => v_pub=0x0000000000000010, note0=0x2F0000000000000F, note1=0x0\n"
        " OUT=> v_pub=0x000000000000000B, note0=0x1A00000000000012,"
        " note1=0x1500000000000002");

    libff::enter_block("Instantiate merkle tree for the tests", true);
    merkle_tree_field<FieldT, HashTreeT<FieldT>> test_merkle_tree(TreeDepth);
    libff::leave_block("Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1
    // -- //
    libff::enter_block("Create joinsplit_input", true);
    // Create the zeth note data for the commitment we will insert in the tree
    // (commitment to spend in this test)
    bits256 trap_r_bits256 = bits256::from_hex(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF");
    bits64 value_bits64 = bits64::from_hex("2F0000000000000F");
    bits256 a_sk_bits256 = bits256::from_hex(
        "FF0000000000000000000000000000000000000000000000000000000000000F");
    bits256 rho_bits256 = bits256::from_hex(
        "FFFF000000000000000000000000000000000000000000000000000000009009");
    bits256 a_pk_bits256 = bits256::from_hex(
        "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49");
    bits256 nf_bits256 = bits256::from_hex(
        "ff2f41920346251f6e7c67062149f98bc90c915d3d3020927ca01deab5da0fd7");
    FieldT cm_field = FieldT(
        "1042337073265819561558789652115525918926201435246168644097060092"
        "42461667751082");
    const size_t address_commitment = 1;
    libff::bit_vector address_bits;
    for (size_t i = 0; i < TreeDepth; ++i) {
        address_bits.push_back((address_commitment >> i) & 0x1);
    }
    bits256 h_sig = bits256::from_hex(
        "6838aac4d8247655715d3dfb9b32573da2b7d3360ba89ccdaaa7923bb24c99f7");
    bits256 phi = bits256::from_hex(
        "403794c0e20e3bf36b820d8f7aef5505e5d1c7ac265d5efbcc3030a74a3f701b");

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree.set_value(address_commitment, cm_field);
    FieldT updated_root_value = test_merkle_tree.get_root();
    std::vector<FieldT> path = test_merkle_tree.get_path(address_commitment);

    // JS Inputs
    std::array<joinsplit_input<FieldT, TreeDepth>, 2> inputs;
    inputs[0] = joinsplit_input<FieldT, TreeDepth>(
        std::vector<FieldT>(path),
        bits_addr<TreeDepth>::from_vector(address_bits),
        zeth_note(a_pk_bits256, value_bits64, rho_bits256, trap_r_bits256),
        bits256(a_sk_bits256),
        bits256(nf_bits256));
    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path
    // check Doesn't count in such case
    zeth_note note_input1(
        a_pk_bits256,
        bits64::from_hex("0000000000000000"),
        rho_bits256,
        trap_r_bits256);
    inputs[1] = joinsplit_input<FieldT, TreeDepth>(
        std::move(path),
        bits_addr<TreeDepth>::from_vector(address_bits),
        note_input1,
        a_sk_bits256,
        nf_bits256);
    libff::leave_block("Create joinsplit_input", true);

    libff::enter_block("Create JSOutput/zeth_note", true);
    bits256 a_pk_out_bits256 = bits256::from_hex(
        "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b");
    const bits256 &rho_out_bits256 = zero_bits256;
    bits256 trap_r_out_bits256 = bits256::from_hex(
        "11000000000000990000000000000099000000000000007700000000000000FF");

    zeth_note note_output0(
        a_pk_out_bits256,
        bits64::from_hex("1A00000000000012"),
        rho_out_bits256,
        trap_r_out_bits256);
    zeth_note note_output1(
        a_pk_out_bits256,
        bits64::from_hex("1500000000000002"),
        rho_out_bits256,
        trap_r_out_bits256);
    std::array<zeth_note, 2> outputs;
    outputs[0] = note_output0;
    outputs[1] = note_output1;
    libff::leave_block("Create JSOutput/zeth_note", true);

    libff::enter_block("Generate proof", true);
    // (RHS) 0x1A00000000000012 + 0x1500000000000002 + 0x000000000000000B =
    // 2F0000000000000F + 0x0000000000000010 + 0x0 (LHS)
    extended_proof<ppT, snarkT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        bits64::from_hex("0000000000000010"), // v_pub_in = 0x0000000000000010
        bits64::from_hex("000000000000000B"), // v_pub_out = 0x000000000000000B
        h_sig,
        phi,
        keypair.pk);
    libff::leave_block("Generate proof", true);

    libff::enter_block("Verify proof", true);
    // Get the verification key
    typename snarkT::VerificationKeyT vk = keypair.vk;
    bool res = snarkT::verify(
        ext_proof.get_primary_inputs(), ext_proof.get_proof(), vk);
    std::cout << "Does the proof verfy? " << res << std::endl;
    libff::leave_block("Verify proof", true);

    std::cout << "[DEBUG] Displaying the extended proof" << std::endl;
    ext_proof.write_json(std::cout);

    return res;
}

template<typename snarkT>
bool TestValidJS2In2Deposit(
    const prover<snarkT> &prover, const typename snarkT::KeypairT &keypair)
{
    // --- General setup for the tests --- //
    libff::print_header(
        "Starting test:\n"
        " IN => v_pub=0x6124FEE993BC0000, note0=0x0, note1=0x0\n"
        " OUT=> v_pub=0x0, note0=0x3782DACE9D900000, note1=0x29A2241AF62C0000");

    libff::enter_block("Instantiate merkle tree for the tests", true);
    merkle_tree_field<FieldT, HashTreeT<FieldT>> test_merkle_tree(TreeDepth);
    libff::leave_block("Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1
    // -- //
    libff::enter_block("Create joinsplit_input", true);
    // Create the zeth note data for the commitment we will insert in the tree
    // (commitment to spend in this test)
    bits256 trap_r_bits256 = bits256::from_hex(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF");
    bits256 a_sk_bits256 = bits256::from_hex(
        "FF0000000000000000000000000000000000000000000000000000000000000F");
    bits256 rho_bits256 = bits256::from_hex(
        "FFFF000000000000000000000000000000000000000000000000000000009009");
    bits256 a_pk_bits256 = bits256::from_hex(
        "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49");
    bits256 nf_bits256 = bits256::from_hex(
        "ff2f41920346251f6e7c67062149f98bc90c915d3d3020927ca01deab5da0fd7");
    FieldT cm_field = FieldT("8049045390937310931330301778888084231593485252743"
                             "182393007013989361193264682");

    const size_t address_commitment = 1;
    libff::bit_vector address_bits;
    for (size_t i = 0; i < TreeDepth; ++i) {
        address_bits.push_back((address_commitment >> i) & 0x1);
    }
    bits256 h_sig = bits256::from_hex(
        "6838aac4d8247655715d3dfb9b32573da2b7d3360ba89ccdaaa7923bb24c99f7");
    bits256 phi = bits256::from_hex(
        "403794c0e20e3bf36b820d8f7aef5505e5d1c7ac265d5efbcc3030a74a3f701b");

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree.set_value(address_commitment, cm_field);
    FieldT updated_root_value = test_merkle_tree.get_root();
    std::vector<FieldT> path = test_merkle_tree.get_path(address_commitment);

    // JS Inputs
    std::array<joinsplit_input<FieldT, TreeDepth>, 2> inputs;
    zeth_note note_input0(
        a_pk_bits256,
        bits64::from_hex("0000000000000000"),
        rho_bits256,
        trap_r_bits256);
    inputs[0] = joinsplit_input<FieldT, TreeDepth>(
        std::vector<FieldT>(path),
        bits_addr<TreeDepth>::from_vector(address_bits),
        note_input0,
        a_sk_bits256,
        nf_bits256);
    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path
    // check Doesn't count in such case
    zeth_note note_input1(
        a_pk_bits256,
        bits64::from_hex("0000000000000000"),
        rho_bits256,
        trap_r_bits256);
    inputs[1] = joinsplit_input<FieldT, TreeDepth>(
        std::move(path),
        bits_addr<TreeDepth>::from_vector(address_bits),
        note_input1,
        a_sk_bits256,
        nf_bits256);
    libff::leave_block("Create joinsplit_input", true);

    libff::enter_block("Create JSOutput/zeth_note", true);
    bits256 a_pk_out_bits256 = bits256::from_hex(
        "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b");
    const bits256 &rho_out_bits256 = zero_bits256;
    bits256 trap_r_out_bits256 = bits256::from_hex(
        "11000000000000990000000000000099000000000000007700000000000000FF");
    zeth_note note_output0(
        a_pk_out_bits256,
        bits64::from_hex("3782DACE9D900000"),
        rho_out_bits256,
        trap_r_out_bits256);
    zeth_note note_output1(
        a_pk_out_bits256,
        bits64::from_hex("29A2241AF62C0000"),
        rho_out_bits256,
        trap_r_out_bits256);
    std::array<zeth_note, 2> outputs;
    outputs[0] = note_output0;
    outputs[1] = note_output1;
    libff::leave_block("Create JSOutput/zeth_note", true);

    libff::enter_block("Generate proof", true);
    // RHS = 0x0 + 0x3782DACE9D900000 + 0x29A2241AF62C0000 = 0x6124FEE993BC0000
    // (LHS)
    extended_proof<ppT, snarkT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        // v_pub_in = 0x6124FEE993BC0000
        bits64::from_hex("6124FEE993BC0000"),
        // v_pub_out = 0x000000000000000B
        bits64::from_hex("0000000000000000"),
        h_sig,
        phi,
        keypair.pk);
    libff::leave_block("Generate proof", true);

    libff::enter_block("Verify proof", true);
    // Get the verification key
    typename snarkT::VerificationKeyT vk = keypair.vk;
    bool res = snarkT::verify(
        ext_proof.get_primary_inputs(), ext_proof.get_proof(), vk);

    std::cout << "[DEBUG] Displaying the extended proof" << std::endl;
    ext_proof.write_json(std::cout);

    std::cout << "Does the proof verify? " << res << std::endl;
    libff::leave_block("Verify proof", true);

    return res;
}

template<typename snarkT>
bool TestInvalidJS2In2(
    const prover<snarkT> &prover, const typename snarkT::KeypairT &keypair)
{
    // --- General setup for the tests --- //
    libff::print_header(
        "Starting test:\n"
        " IN => v_pub=0xFA80001400000000, note0=0x0, note1=0x0\n"
        " OUT=> v_pub=0x0, note0=0x8530000A00000001, note1=0x7550000A00000000");

    libff::enter_block("Instantiate merkle tree for the tests", true);
    merkle_tree_field<FieldT, HashTreeT<FieldT>> test_merkle_tree(TreeDepth);
    libff::leave_block("Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1
    // -- //
    libff::enter_block("Create joinsplit_input", true);
    // Create the zeth note data for the commitment we will insert in the tree
    // (commitment to spend in this test)
    bits256 trap_r_bits256 = bits256::from_hex(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF");
    bits256 a_sk_bits256 = bits256::from_hex(
        "FF0000000000000000000000000000000000000000000000000000000000000F");
    bits256 rho_bits256 = bits256::from_hex(
        "FFFF000000000000000000000000000000000000000000000000000000009009");
    bits256 a_pk_bits256 = bits256::from_hex(
        "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49");
    bits256 nf_bits256 = bits256::from_hex(
        "ff2f41920346251f6e7c67062149f98bc90c915d3d3020927ca01deab5da0fd7");
    FieldT cm_field = FieldT("8049045390937310931330301778888084231593485252743"
                             "182393007013989361193264682");

    const size_t address_commitment = 1;
    libff::bit_vector address_bits;
    for (size_t i = 0; i < TreeDepth; ++i) {
        address_bits.push_back((address_commitment >> i) & 0x1);
    }
    bits256 h_sig = bits256::from_hex(
        "6838aac4d8247655715d3dfb9b32573da2b7d3360ba89ccdaaa7923bb24c99f7");
    bits256 phi = bits256::from_hex(
        "403794c0e20e3bf36b820d8f7aef5505e5d1c7ac265d5efbcc3030a74a3f701b");

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree.set_value(address_commitment, cm_field);
    FieldT updated_root_value = test_merkle_tree.get_root();
    std::vector<FieldT> path = test_merkle_tree.get_path(address_commitment);

    // JS Inputs
    zeth_note note_input0(
        a_pk_bits256,
        bits64::from_hex("0000000000000000"),
        rho_bits256,
        trap_r_bits256);
    std::array<joinsplit_input<FieldT, TreeDepth>, 2> inputs;
    inputs[0] = joinsplit_input<FieldT, TreeDepth>(
        std::vector<FieldT>(path),
        bits_addr<TreeDepth>::from_vector(address_bits),
        note_input0,
        a_sk_bits256,
        nf_bits256);
    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path
    // check Doesn't count in such case
    zeth_note note_input1(
        a_pk_bits256,
        bits64::from_hex("0000000000000000"),
        rho_bits256,
        trap_r_bits256);
    inputs[1] = joinsplit_input<FieldT, TreeDepth>(
        std::move(path),
        bits_addr<TreeDepth>::from_vector(address_bits),
        note_input1,
        a_sk_bits256,
        nf_bits256);
    libff::leave_block("Create joinsplit_input", true);

    libff::enter_block("Create JSOutput/zeth_note", true);
    bits256 a_pk_out_bits256 = bits256::from_hex(
        "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b");
    const bits256 &rho_out_bits256 = zero_bits256;
    bits256 trap_r_out_bits256 = bits256::from_hex(
        "11000000000000990000000000000099000000000000007700000000000000FF");

    // 0x8530000A00000000 = 9.597170848876199937 ETH
    zeth_note note_output0(
        a_pk_out_bits256,
        bits64::from_hex("8530000A00000001"),
        rho_out_bits256,
        trap_r_out_bits256);
    // 0x7550000A00000000 = 8.453256543524093952 ETH
    zeth_note note_output1(
        a_pk_out_bits256,
        bits64::from_hex("7550000A00000000"),
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
    extended_proof<ppT, snarkT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        // vpub_in = 0xFA80001400000000 = 18.050427392400293888 ETH
        bits64::from_hex("FA80001400000000"),
        // vpub_out = 0x0
        bits64::from_hex("0000000000000000"),
        h_sig,
        phi,
        keypair.pk);
    libff::leave_block("Generate proof", true);

    libff::enter_block("Verify proof", true);
    // Get the verification key
    typename snarkT::VerificationKeyT vk = keypair.vk;
    bool res = snarkT::verify(
        ext_proof.get_primary_inputs(), ext_proof.get_proof(), vk);
    std::cout << "Does the proof verify ? " << res << std::endl;
    libff::leave_block("Verify proof", true);

    std::cout << "[DEBUG] Displaying the extended proof" << std::endl;
    ext_proof.write_json(std::cout);

    return res;
}

template<typename snarkT> static void run_prover_tests()
{
    // Run the trusted setup once for all tests, and keep the keypair in memory
    // for the duration of the tests
    prover<snarkT> proverJS2to2;

    typename snarkT::KeypairT keypair = proverJS2to2.generate_trusted_setup();
    bool res = false;

    res = TestValidJS2In2Case1(proverJS2to2, keypair);
    ASSERT_TRUE(res);

    res = TestValidJS2In2Case2(proverJS2to2, keypair);
    ASSERT_TRUE(res);

    res = TestValidJS2In2Case3(proverJS2to2, keypair);
    ASSERT_TRUE(res);

    res = TestValidJS2In2Deposit(proverJS2to2, keypair);
    ASSERT_TRUE(res);

    // The following is expected to throw an exception because LHS =/= RHS.
    // Ensure that the exception is thrown.
    ASSERT_THROW(
        (res = TestInvalidJS2In2(proverJS2to2, keypair)),
        std::invalid_argument);

    try {
        res = false;
        res = TestInvalidJS2In2(proverJS2to2, keypair);
        res = true;
    } catch (const std::invalid_argument &e) {
        std::cerr << "Invalid argument exception: " << e.what() << '\n';
    }
    ASSERT_FALSE(res);
}

TEST(MainTestsGroth16, ProofGenAndVerifJS2to2)
{
    run_prover_tests<groth16_snark<ppT>>();
}

TEST(MainTestsPghr12, ProofGenAndVerifJS2to2)
{
    run_prover_tests<pghr13_snark<ppT>>();
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
