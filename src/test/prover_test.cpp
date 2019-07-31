#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure to keep a local merkle tree
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Have access to a chrono to measure the rough time of execution of a set of instructions
#include <chrono>
#include "snarks_alias.hpp"
// Import only the core components of the SNARK (not the API components)
#include "snarks_core_imports.hpp"
#include "libsnark_helpers/libsnark_helpers.hpp"
#include "circuits/sha256/sha256_ethereum.hpp"
#include "circuit-wrapper.hpp"
#include "util.hpp"

using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT; // Should be alt_bn128 in the CMakeLists.txt
typedef sha256_ethereum<FieldT> HashT; // We use our hash function to do the tests
typedef MiMC_mp_gadget<FieldT> HashTreeT; // We use our hash function to do the tests

namespace {

bool TestValidJS2In2Case1(
    CircuitWrapper<FieldT, 2, 2> &prover,
    libzeth::keyPairT<ppT> keypair
) {
    // --- General setup for the tests --- //
    libff::print_header("test JS 2-2: IN => vpub_in = 0x0, note1 = 0x2F0000000000000F, note2 = 0x0 || OUT => vpub_out = 0x1700000000000007, note1 = 0x1800000000000008, note2 = 0x0");

    libff::enter_block("[START] Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    // Note: `make_unique` should be C++14 compliant, but here we use c++11, so we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>> test_merkle_tree = std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>>(
        new merkle_tree_field<FieldT, HashTreeT>(
            ZETH_MERKLE_TREE_DEPTH
            )
    );
    libff::leave_block("[END] Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1 -- //
    libff::enter_block("[BEGIN] Create JSInput", true);
    // Create the zeth note data for the commitment we will insert in the tree (commitment to spend in this test)
    bits384 trap_r_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector("0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF"));
    bits64 value_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector("2F0000000000000F"));
    bits256 a_sk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("FF0000000000000000000000000000000000000000000000000000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("FFFF000000000000000000000000000000000000000000000000000000009009"));
    bits256 a_pk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"));
    bits256 nf_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("69f12603c2cfb2acf6f80a8f72cbdeb4417a6b8c7290e793c4d22830c4b35c5f"));

    // Converted from old hex string "823d19485c94f74b4739ba7d17e4b434693086a996fa2e8d1438a91b1c220331" (big-endian)
    FieldT cm_field = FieldT("58908622481300953619931625205032657328696563920286427818865722362743092282161");
    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm_field);
    FieldT updated_root_value = test_merkle_tree->get_root();
    std::vector<FieldT> path = test_merkle_tree->get_path(address_commitment);

    // JS Inputs: 1 note of value > 0 to spend, and a dummy note
    ZethNote note_input(
        a_pk_bits256,
        value_bits64,
        rho_bits256,
        trap_r_bits384
    );
    ZethNote note_dummy_input(
        a_pk_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")),
        get_bits256_from_vector(hexadecimal_digest_to_binary_vector("AAAA00000000000000000000000000000000000000000000000000000000EEEE")),
        trap_r_bits384
    );
    JSInput<FieldT> input(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input,
        a_sk_bits256,
        nf_bits256
    );
    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path check
    // Doesn't count in such case
    JSInput<FieldT> input_dummy(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_dummy_input,
        a_sk_bits256,
        nf_bits256
    );
    std::array<JSInput<FieldT>, 2> inputs;
    inputs[0] = input;
    inputs[1] = input_dummy;
    libff::leave_block("[END] Create JSInput", true);

    libff::enter_block("[BEGIN] Create JSOutput/ZethNote", true);
    bits64 value_out_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector("1800000000000008"));
    bits256 a_pk_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"));
    bits256 rho_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("1111000000000000000000000000000000000000000000000000000000009777"));
    bits384 trap_r_out_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector("11000000000000990000000000000099000000000000007700000000000000FF00000000000000FF0000000000000777"));
    ZethNote note_output(
        a_pk_out_bits256,
        value_out_bits64,
        rho_out_bits256,
        trap_r_out_bits384
    );
    ZethNote note_dummy_output(
        a_pk_out_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")),
        rho_out_bits256,
        trap_r_out_bits384
    );
    bits64 value_pub_out_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector("1700000000000007"));
    std::array<ZethNote, 2> outputs;
    outputs[0] = note_output;
    outputs[1] = note_dummy_output;
    libff::leave_block("[END] Create JSOutput/ZethNote", true);

    libff::enter_block("[BEGIN] Generate proof", true);
    extended_proof<ppT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")), // vpub_in = 0
        value_pub_out_bits64,
        keypair.pk
    );
    libff::leave_block("[END] Generate proof", true);

    libff::enter_block("[BEGIN] Verify proof", true);
    // Get the verification key
    libzeth::verificationKeyT<ppT> vk = keypair.vk;
    bool res = libzeth::verify(ext_proof, vk);
    std::cout << "Does the proof verify? " << res << std::endl;
    libff::leave_block("[END] Verify proof", true);

    return res;
}


bool TestValidJS2In2Case2(
    CircuitWrapper<FieldT, 2, 2> &prover,
    libzeth::keyPairT<ppT> keypair
) {
    libff::print_header("Starting test: IN => v_pub = 0, note1 = 0x2F0000000000000F, note2 = 0x0 || OUT => v_pub = 0x000000000000000B, note1 = 0x1A00000000000002, note2 = 0x1500000000000002");

    libff::enter_block("[START] Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    // Note: `make_unique` should be C++14 compliant, but here we use c++11, so we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>> test_merkle_tree = std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>>(
        new merkle_tree_field<FieldT, HashTreeT>(
            ZETH_MERKLE_TREE_DEPTH
            )
    );
    libff::leave_block("[END] Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1 -- //
    libff::enter_block("[BEGIN] Create JSInput", true);
    // Create the zeth note data for the commitment we will insert in the tree (commitment to spend in this test)
    bits384 trap_r_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector("0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF"));
    bits256 a_sk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("FF0000000000000000000000000000000000000000000000000000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("FFFF000000000000000000000000000000000000000000000000000000009009"));
    bits256 a_pk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"));
    bits256 nf_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("69f12603c2cfb2acf6f80a8f72cbdeb4417a6b8c7290e793c4d22830c4b35c5f"));

    // We compute the commitment to insert it in the merkle tree we use for the tests
    // Converted from old hex string "823d19485c94f74b4739ba7d17e4b434693086a996fa2e8d1438a91b1c220331" (big-endian)
    FieldT cm_field = FieldT("58908622481300953619931625205032657328696563920286427818865722362743092282161");
    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm_field);
    FieldT updated_root_value = test_merkle_tree->get_root();
    std::vector<FieldT> path = test_merkle_tree->get_path(address_commitment);

    // JS Inputs
    ZethNote note_input1(
        a_pk_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("2F0000000000000F")), // value associated with the commitment cm_bits256
        rho_bits256,
        trap_r_bits384
    );
    ZethNote note_input2(
        a_pk_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")),
        rho_bits256,
        trap_r_bits384
    );
    JSInput<FieldT> input1(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input1,
        a_sk_bits256,
        nf_bits256
    );
    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path check
    // Doesn't count in such case
    JSInput<FieldT> input2(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input2,
        a_sk_bits256,
        nf_bits256
    );
    std::array<JSInput<FieldT>, 2> inputs;
    inputs[0] = input1;
    inputs[1] = input2;
    libff::leave_block("[END] Create JSInput", true);

    libff::enter_block("[BEGIN] Create JSOutput/ZethNote", true);
    bits256 a_pk_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"));
    bits256 rho_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("1111000000000000000000000000000000000000000000000000000000009777"));
    bits384 trap_r_out_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector("11000000000000990000000000000099000000000000007700000000000000FF00000000000000FF0000000000000777"));
    ZethNote note_output1(
        a_pk_out_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("1A00000000000002")),
        rho_out_bits256,
        trap_r_out_bits384
    );
    ZethNote note_output2(
        a_pk_out_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("1500000000000002")),
        rho_out_bits256,
        trap_r_out_bits384
    );
    std::array<ZethNote, 2> outputs;
    outputs[0] = note_output1;
    outputs[1] = note_output2;
    libff::leave_block("[END] Create JSOutput/ZethNote", true);

    libff::enter_block("[BEGIN] Generate proof", true);
    // RHS = 0x1A00000000000002 + 0x1500000000000002 + 0x000000000000000B = 2F0000000000000F (LHS)
    extended_proof<ppT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")), // vpub_in = 0x0
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("000000000000000B")), // vpub_out = 0x000000000000000B
        keypair.pk
    );
    libff::leave_block("[END] Generate proof", true);

    libff::enter_block("[BEGIN] Verify proof", true);
    // Get the verification key
    libzeth::verificationKeyT<ppT> vk = keypair.vk;
    bool res = libzeth::verify(ext_proof, vk);
    std::cout << "Does the proof verify? " << res << std::endl;
    libff::leave_block("[END] Verify proof", true);

    return res;
}


bool TestValidJS2In2Case3(
    CircuitWrapper<FieldT, 2, 2> &prover,
    libzeth::keyPairT<ppT> keypair
) {
    // --- General setup for the tests --- //
    libff::print_header("Starting test: IN => v_pub = 0x0000000000000010, note1 = 0x2F0000000000000F, note2 = 0x0 || OUT => v_pub = 0x000000000000000B, note1 = 0x1A00000000000012, note2 = 0x1500000000000002");

    libff::enter_block("[START] Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    // Note: `make_unique` should be C++14 compliant, but here we use c++11, so we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>> test_merkle_tree = std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>>(
        new merkle_tree_field<FieldT, HashTreeT>(
            ZETH_MERKLE_TREE_DEPTH
            )
    );
    libff::leave_block("[END] Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1 -- //
    libff::enter_block("[BEGIN] Create JSInput", true);
    // Create the zeth note data for the commitment we will insert in the tree (commitment to spend in this test)
    bits384 trap_r_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector("0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF"));
    bits256 a_sk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("FF0000000000000000000000000000000000000000000000000000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("FFFF000000000000000000000000000000000000000000000000000000009009"));
    bits256 a_pk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"));
    bits256 nf_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("69f12603c2cfb2acf6f80a8f72cbdeb4417a6b8c7290e793c4d22830c4b35c5f"));

    // We compute the commitment to insert it in the merkle tree we use for the tests
    // Converted from old hex string "823d19485c94f74b4739ba7d17e4b434693086a996fa2e8d1438a91b1c220331" (big-endian)
    FieldT cm_field = FieldT("58908622481300953619931625205032657328696563920286427818865722362743092282161");
    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm_field);
    FieldT updated_root_value = test_merkle_tree->get_root();
    std::vector<FieldT> path = test_merkle_tree->get_path(address_commitment);

    // JS Inputs
    ZethNote note_input1(
        a_pk_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("2F0000000000000F")), // value associated with the commitment cm_bits256
        rho_bits256,
        trap_r_bits384
    );
    ZethNote note_input2(
        a_pk_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")),
        rho_bits256,
        trap_r_bits384
    );
    JSInput<FieldT> input1(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input1,
        a_sk_bits256,
        nf_bits256
    );
    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path check
    // Doesn't count in such case
    JSInput<FieldT> input2(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input2,
        a_sk_bits256,
        nf_bits256
    );
    std::array<JSInput<FieldT>, 2> inputs;
    inputs[0] = input1;
    inputs[1] = input2;
    libff::leave_block("[END] Create JSInput", true);

    libff::enter_block("[BEGIN] Create JSOutput/ZethNote", true);
    bits256 a_pk_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"));
    bits256 rho_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("1111000000000000000000000000000000000000000000000000000000009777"));
    bits384 trap_r_out_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector("11000000000000990000000000000099000000000000007700000000000000FF00000000000000FF0000000000000777"));
    ZethNote note_output1(
        a_pk_out_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("1A00000000000012")),
        rho_out_bits256,
        trap_r_out_bits384
    );
    ZethNote note_output2(
        a_pk_out_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("1500000000000002")),
        rho_out_bits256,
        trap_r_out_bits384
    );
    std::array<ZethNote, 2> outputs;
    outputs[0] = note_output1;
    outputs[1] = note_output2;
    libff::leave_block("[END] Create JSOutput/ZethNote", true);

    libff::enter_block("[BEGIN] Generate proof", true);
    // (RHS) 0x1A00000000000012 + 0x1500000000000002 + 0x000000000000000B = 2F0000000000000F + 0x0000000000000010 + 0x0 (LHS)
    extended_proof<ppT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000010")), // v_pub_in = 0x0000000000000010
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("000000000000000B")), // v_pub_out = 0x000000000000000B
        keypair.pk
    );
    libff::leave_block("[END] Generate proof", true);

    libff::enter_block("[BEGIN] Verify proof", true);
    // Get the verification key
    libzeth::verificationKeyT<ppT> vk = keypair.vk;
    bool res = libzeth::verify(ext_proof, vk);
    std::cout << "Does the proof verfy? " << res << std::endl;
    libff::leave_block("[END] Verify proof", true);

    return res;
}

bool TestValidJS2In2Deposit(
    CircuitWrapper<FieldT, 2, 2> &prover,
    libzeth::keyPairT<ppT> keypair
) {
    // --- General setup for the tests --- //
    libff::print_header("Starting test: IN => v_pub = 0x6124FEE993BC0000, note1 = 0x0, note2 = 0x0 || OUT => v_pub = 0x0, note1 = 0x3782DACE9D900000, note2 = 0x29A2241AF62C0000");

    libff::enter_block("[START] Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    // Note: `make_unique` should be C++14 compliant, but here we use c++11, so we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>> test_merkle_tree = std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>>(
        new merkle_tree_field<FieldT, HashTreeT>(
            ZETH_MERKLE_TREE_DEPTH
            )
    );
    libff::leave_block("[END] Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1 -- //
    libff::enter_block("[BEGIN] Create JSInput", true);
    // Create the zeth note data for the commitment we will insert in the tree (commitment to spend in this test)
    bits384 trap_r_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector("0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF"));
    bits256 a_sk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("FF0000000000000000000000000000000000000000000000000000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("FFFF000000000000000000000000000000000000000000000000000000009009"));
    bits256 a_pk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"));
    bits256 nf_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("69f12603c2cfb2acf6f80a8f72cbdeb4417a6b8c7290e793c4d22830c4b35c5f"));

    // We compute a commitment to insert it in the merkle tree we use for the tests
    // Converted from old hex string "823d19485c94f74b4739ba7d17e4b434693086a996fa2e8d1438a91b1c220331" (big-endian)
    FieldT cm_field = FieldT("58908622481300953619931625205032657328696563920286427818865722362743092282161");
    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm_field);
    FieldT updated_root_value = test_merkle_tree->get_root();
    std::vector<FieldT> path = test_merkle_tree->get_path(address_commitment);

    // JS Inputs
    ZethNote note_input1(
        a_pk_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")),
        rho_bits256,
        trap_r_bits384
    );
    ZethNote note_input2(
        a_pk_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")),
        rho_bits256,
        trap_r_bits384
    );
    JSInput<FieldT> input1(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input1,
        a_sk_bits256,
        nf_bits256
    );
    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path check
    // Doesn't count in such case
    JSInput<FieldT> input2(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input2,
        a_sk_bits256,
        nf_bits256
    );
    std::array<JSInput<FieldT>, 2> inputs;
    inputs[0] = input1;
    inputs[1] = input2;
    libff::leave_block("[END] Create JSInput", true);

    libff::enter_block("[BEGIN] Create JSOutput/ZethNote", true);
    bits256 a_pk_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"));
    bits256 rho_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("1111000000000000000000000000000000000000000000000000000000009777"));
    bits384 trap_r_out_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector("11000000000000990000000000000099000000000000007700000000000000FF00000000000000FF0000000000000777"));
    ZethNote note_output1(
        a_pk_out_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("3782DACE9D900000")),
        rho_out_bits256,
        trap_r_out_bits384
    );
    ZethNote note_output2(
        a_pk_out_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("29A2241AF62C0000")),
        rho_out_bits256,
        trap_r_out_bits384
    );
    std::array<ZethNote, 2> outputs;
    outputs[0] = note_output1;
    outputs[1] = note_output2;
    libff::leave_block("[END] Create JSOutput/ZethNote", true);

    libff::enter_block("[BEGIN] Generate proof", true);
    // RHS = 0x0 + 0x3782DACE9D900000 + 0x29A2241AF62C0000 = 0x6124FEE993BC0000 (LHS)
    extended_proof<ppT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("6124FEE993BC0000")), // v_pub_in = 0x6124FEE993BC0000
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")), // v_pub_out = 0x000000000000000B
        keypair.pk
    );
    libff::leave_block("[END] Generate proof", true);

    libff::enter_block("[BEGIN] Verify proof", true);
    // Get the verification key
    libzeth::verificationKeyT<ppT> vk = keypair.vk;
    bool res = libzeth::verify(ext_proof, vk);

    ext_proof.dump_primary_inputs();
    std::cout << "Does the proof verify? " << res << std::endl;
    libff::leave_block("[END] Verify proof", true);

    return res;
}

bool TestInvalidJS2In2(
    CircuitWrapper<FieldT, 2, 2> &prover,
    libzeth::keyPairT<ppT> keypair
) {
    // --- General setup for the tests --- //
    libff::print_header("Starting test: IN => v_pub = 0xFA80001400000000, note1 = 0x0, note2 = 0x0 || OUT => v_pub = 0x0, note1 = 0x8530000A00000001, note2 = 0x7550000A00000000");

    libff::enter_block("[START] Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    // Note: `make_unique` should be C++14 compliant, but here we use c++11, so we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>> test_merkle_tree = std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>>(
        new merkle_tree_field<FieldT, HashTreeT>(
            ZETH_MERKLE_TREE_DEPTH
            )
    );
    libff::leave_block("[END] Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1 -- //
    libff::enter_block("[BEGIN] Create JSInput", true);
    // Create the zeth note data for the commitment we will insert in the tree (commitment to spend in this test)
    bits384 trap_r_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector("0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF"));
    bits256 a_sk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("FF0000000000000000000000000000000000000000000000000000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("FFFF000000000000000000000000000000000000000000000000000000009009"));
    bits256 a_pk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"));
    bits256 nf_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("69f12603c2cfb2acf6f80a8f72cbdeb4417a6b8c7290e793c4d22830c4b35c5f"));

    // We compute a commitment to insert it in the merkle tree we use for the tests
    // Converted from old hex string "823d19485c94f74b4739ba7d17e4b434693086a996fa2e8d1438a91b1c220331" (big-endian)
    FieldT cm_field = FieldT("58908622481300953619931625205032657328696563920286427818865722362743092282161");
    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm_field);
    FieldT updated_root_value = test_merkle_tree->get_root();
    std::vector<FieldT> path = test_merkle_tree->get_path(address_commitment);

    // JS Inputs
    ZethNote note_input1(
        a_pk_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")),
        rho_bits256,
        trap_r_bits384
    );
    ZethNote note_input2(
        a_pk_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")),
        rho_bits256,
        trap_r_bits384
    );
    JSInput<FieldT> input1(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input1,
        a_sk_bits256,
        nf_bits256
    );
    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path check
    // Doesn't count in such case
    JSInput<FieldT> input2(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input2,
        a_sk_bits256,
        nf_bits256
    );
    std::array<JSInput<FieldT>, 2> inputs;
    inputs[0] = input1;
    inputs[1] = input2;
    libff::leave_block("[END] Create JSInput", true);

    libff::enter_block("[BEGIN] Create JSOutput/ZethNote", true);
    bits256 a_pk_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"));
    bits256 rho_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("1111000000000000000000000000000000000000000000000000000000009777"));
    bits384 trap_r_out_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector("11000000000000990000000000000099000000000000007700000000000000FF00000000000000FF0000000000000777"));
    ZethNote note_output1(
        a_pk_out_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("8530000A00000001")), // 0x8530000A00000000 = 9.597170848876199937 ETH
        rho_out_bits256,
        trap_r_out_bits384
    );
    ZethNote note_output2(
        a_pk_out_bits256,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("7550000A00000000")), // 0x7550000A00000000 = 8.453256543524093952 ETH
        rho_out_bits256,
        trap_r_out_bits384
    );
    std::array<ZethNote, 2> outputs;
    outputs[0] = note_output1;
    outputs[1] = note_output2;
    libff::leave_block("[END] Create JSOutput/ZethNote", true);

    libff::enter_block("[BEGIN] Generate proof", true);
    // LHS = 0xFA80001400000000 (18.050427392400293888 ETH) =/= 0x8530000A00000001 (9.597170848876199937 ETH) + 0x7550000A00000000 (8.453256543524093952 ETH) = RHS
    // LHS = 18.050427392400293888 ETH
    // RHS = 18.050427392400293889 ETH (1 wei higher than LHS)
    extended_proof<ppT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("FA80001400000000")), // vpub_in = 0xFA80001400000000 = 18.050427392400293888 ETH
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")), // vpub_out = 0x0
        keypair.pk
    );
    libff::leave_block("[END] Generate proof", true);

    libff::enter_block("[BEGIN] Verify proof", true);
    // Get the verification key
    libzeth::verificationKeyT<ppT> vk = keypair.vk;
    bool res = libzeth::verify(ext_proof, vk);
    std::cout << "Does the proof verify ? " << res << std::endl;
    libff::leave_block("[END] Verify proof", true);

    return res;
}


TEST(MainTests, ProofGenAndVerifJS2to2) {
    // Run the trusted setup once for all tests, and keep the keypair in memory for the duration of the tests
    CircuitWrapper<FieldT, 2, 2> proverJS2to2;
    libzeth::keyPairT<ppT> keypair = proverJS2to2.generate_trusted_setup();
    bool res = false;

    res = TestValidJS2In2Case1(proverJS2to2, keypair);
    std::cout << "[TestValidJS2In2Case1] Expected (True), Obtained result: " << res << std::endl;
    ASSERT_TRUE(res);


    res = TestValidJS2In2Case2(proverJS2to2, keypair);
    std::cout << "[TestValidJS2In2Case2] Expected (True), Obtained result: " << res << std::endl;
    ASSERT_TRUE(res);

    res = TestValidJS2In2Case3(proverJS2to2, keypair);
    std::cout << "[TestValidJS2In2Case3] Expected (True), Obtained result: " << res << std::endl;
    ASSERT_TRUE(res);

    res = TestValidJS2In2Deposit(proverJS2to2, keypair);
    std::cout << "[TestValidJS2In2Deposit] Expected (True), Obtained result: " << res << std::endl;
    ASSERT_TRUE(res);

    // The following test is expected to throw an exception because the LHS =/= RHS
    try {
        res = TestInvalidJS2In2(proverJS2to2, keypair);
        std::cout << "[TestInvalidJS2In2] Expected (False), Obtained result: " << res << std::endl;
        ASSERT_TRUE(res);
    } catch (const std::invalid_argument& e) {
	  std::cerr << "Invalid argument exception: " << e.what() << '\n';
    }

}

} // namespace

int main(int argc, char **argv) {
    ppT::init_public_params(); // /!\ WARNING: Do once for all tests. Do not forget to do this !!!!
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
