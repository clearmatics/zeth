#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Have access to a chrono to measure the time of execution of a set of instructions
#include <chrono> 

#include "libsnark_helpers/libsnark_helpers.hpp"

// Header to use the sha256_ethereum gadget
#include "sha256/sha256_ethereum.hpp"

#include "circuit-wrapper.cpp"

using namespace libsnark;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT; // Should be alt_bn128 in the CMakeLists.txt
typedef sha256_ethereum<FieldT> HashT; // We use our hash function to do the tests

namespace {

void dump_bit_vector(std::ostream &out, const libff::bit_vector &v)
{
    out << "{";
    for (size_t i = 0; i < v.size() - 1; ++i)
    {
        out << v[i] << ", ";
    }
    out << v[v.size() - 1] << "}\n";
}

bool Test_ValidJS1In1Out(
    CircuitWrapper<1, 1> &prover,
    libsnark::r1cs_ppzksnark_keypair<ppT> keypair
) {
    // --- General setup for the tests --- //
    libff::print_header("Starting test (JS: 1 in, 1 out of same value, and no public value)");

    libff::enter_block("[BEGIN] General setup for the tests", true);
    // Create a merkle tree to run our tests
    // Note: make_unique should be C++14 compliant, but here we use c++11, so we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree<HashT>> test_merkle_tree = std::unique_ptr<libsnark::merkle_tree<HashT>>(
        new libsnark::merkle_tree<HashT>(
            ZETH_MERKLE_TREE_DEPTH,
            HashT::get_digest_len()
        )
    );
    std::ostream &stream = std::cout;
    libff::leave_block("[END] General setup for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1 -- //
    libff::enter_block("[BEGIN] Create JSInput", true);

    char* trap_r_str = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    bits384 trap_r_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector(trap_r_str));

    char* value_str = "2F0000000000000F";
    bits64 value_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_str));

    char* a_sk_str = "FF0000000000000000000000000000000000000000000000000000000000000F";
    bits256 a_sk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(a_sk_str));

    char* rho_str = "FFFF000000000000000000000000000000000000000000000000000000009009";
    bits256 rho_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(rho_str));

    char* rho_254_padded_with_01 = "8FFFC00000000000000000000000000000000000000000000000000000002402";

    char* a_pk_str = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b";
    bits256 a_pk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(a_pk_str));

    char* nf_str = "69f12603c2cfb2acf6f80a8f72cbdeb4417a6b8c7290e793c4d22830c4b35c5f";
    bits256 nf_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(nf_str));

    char* cm_str = "823d19485c94f74b4739ba7d17e4b434693086a996fa2e8d1438a91b1c220331";
    bits256 cm_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(cm_str));

    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;

    test_merkle_tree->set_value(address_commitment, libff::bit_vector(get_vector_from_bits256(cm_bits256)));
    libff::bit_vector root_value = test_merkle_tree->get_root();
    std::vector<libsnark::merkle_authentication_node> path = test_merkle_tree->get_path(address_commitment);

    ZethNote note_input(
        a_pk_bits256,
        value_bits64,
        rho_bits256,
        trap_r_bits384
    );

    JSInput input(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input,
        a_sk_bits256,
        nf_bits256
    );

    std::array<JSInput, 1> inputs;
    inputs.fill(input);

    libff::leave_block("[END] Create JSInput", true);

    libff::enter_block("[BEGIN] Create JSOutput/ZethNote", true);

    char* value_str_out = "2F0000000000000F";
    bits64 value_out_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_str_out));

    char* a_pk_str_out = "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b";
    bits256 a_pk_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(a_pk_str_out));

    char* rho_out_str = "1111000000000000000000000000000000000000000000000000000000009777";
    bits256 rho_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(rho_out_str));

    char* trap_r_out_str = "11000000000000990000000000000099000000000000007700000000000000FF00000000000000FF0000000000000777";
    bits384 trap_r_out_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector(trap_r_out_str));

    ZethNote note_output(
        a_pk_out_bits256,
        value_out_bits64,
        rho_out_bits256,
        trap_r_out_bits384
    );

    char* value_pub_str_out = "0000000000000000";
    bits64 value_pub_out_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_pub_str_out));

    std::array<ZethNote, 1> outputs;
    outputs.fill(note_output);

    libff::leave_block("[END] Create JSOutput/ZethNote", true);

    libff::enter_block("[BEGIN] Generate proof", true);

    extended_proof<ppT> ext_proof = prover.prove(
        get_bits256_from_vector(root_value),
        inputs,
        outputs,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")), // No value in here
        value_pub_out_bits64,
        keypair.pk
    );

    libff::leave_block("[END] Generate proof", true);

    libff::enter_block("[BEGIN] Verify proof", true);

    libsnark::r1cs_ppzksnark_verification_key<ppT> vk = keypair.vk;
    bool res = libsnark::r1cs_ppzksnark_verifier_strong_IC<ppT>(vk, ext_proof.get_primary_input(), ext_proof.get_proof());

    libff::leave_block("[END] Verify proof", true);

    return res;
}

bool Test_InvalidJS1In1Out(
    CircuitWrapper<1, 1> &prover,
    libsnark::r1cs_ppzksnark_keypair<ppT> keypair
) {
    // --- General setup for the tests --- //
    libff::print_header("Starting test (JS: 1 in, 1 out of DIFFERENT value");

    libff::enter_block("[START] General setup for the tests", true);

    // Create a merkle tree to run our tests
    // Note: make_unique should be C++14 compliant, but here we use c++11, so we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree<HashT>> test_merkle_tree = std::unique_ptr<libsnark::merkle_tree<HashT>>(
        new libsnark::merkle_tree<HashT>(
            ZETH_MERKLE_TREE_DEPTH,
            HashT::get_digest_len()
        )
    );
    std::ostream &stream = std::cout;
    libff::leave_block("[END] General setup for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1 -- //
    libff::enter_block("[BEGIN] Create JSInput", true);

    char* trap_r_str = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    bits384 trap_r_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector(trap_r_str));

    char* value_str = "2F0000000000000F";
    bits64 value_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_str));

    char* a_sk_str = "FF0000000000000000000000000000000000000000000000000000000000000F";
    bits256 a_sk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(a_sk_str));

    char* rho_str = "FFFF000000000000000000000000000000000000000000000000000000009009";
    bits256 rho_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(rho_str));

    char* rho_254_padded_with_01 = "8FFFC00000000000000000000000000000000000000000000000000000002402";

    char* a_pk_str = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b";
    bits256 a_pk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(a_pk_str));

    char* nf_str = "69f12603c2cfb2acf6f80a8f72cbdeb4417a6b8c7290e793c4d22830c4b35c5f";
    bits256 nf_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(nf_str));

    char* cm_str = "823d19485c94f74b4739ba7d17e4b434693086a996fa2e8d1438a91b1c220331";
    bits256 cm_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(cm_str));

    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;

    test_merkle_tree->set_value(address_commitment, libff::bit_vector(get_vector_from_bits256(cm_bits256)));
    libff::bit_vector root_value = test_merkle_tree->get_root();
    std::vector<libsnark::merkle_authentication_node> path = test_merkle_tree->get_path(address_commitment);

    ZethNote note_input(
        a_pk_bits256,
        value_bits64,
        rho_bits256,
        trap_r_bits384
    );

    bitsAddr binary_address = get_bitsAddr_from_vector(address_bits);
    JSInput input(
        path,
        address_commitment,
        binary_address,
        note_input,
        a_sk_bits256,
        nf_bits256
    );

    std::array<JSInput, 1> inputs;
    inputs.fill(input);

    libff::leave_block("[END] Create JSInput", true);

    libff::enter_block("[BEGIN] Create JSOutput/ZethNote", true);

    char* value_str_out = "2F000000000000FF"; // > value_str (the JS equality constraint should be violated)
    bits64 value_out_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_str_out));

    char* a_pk_str_out = "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b";
    bits256 a_pk_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(a_pk_str_out));

    char* rho_out_str = "1111000000000000000000000000000000000000000000000000000000009777";
    bits256 rho_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(rho_out_str));

    char* trap_r_out_str = "11000000000000990000000000000099000000000000007700000000000000FF00000000000000FF0000000000000777";
    bits384 trap_r_out_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector(trap_r_out_str));

    ZethNote note_output(
        a_pk_out_bits256,
        value_out_bits64,
        rho_out_bits256,
        trap_r_out_bits384
    );

    char* value_pub_str_out = "0000000000000000";
    bits64 value_pub_out_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_pub_str_out));

    std::array<ZethNote, 1> outputs;
    outputs.fill(note_output);

    libff::leave_block("[END] Create JSOutput/ZethNote", true);

    libff::enter_block("[BEGIN] Generate proof", true);

    extended_proof<ppT> ext_proof = prover.prove(
        get_bits256_from_vector(root_value),
        inputs,
        outputs,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")), // No value in here
        value_pub_out_bits64,
        keypair.pk
    );

    libff::leave_block("[END] Generate proof", true);

    libff::enter_block("[BEGIN] Verify proof", true);

    // Get the verification key
    libsnark::r1cs_ppzksnark_verification_key<ppT> vk = keypair.vk;
    bool res = libsnark::r1cs_ppzksnark_verifier_strong_IC<ppT>(vk, ext_proof.get_primary_input(), ext_proof.get_proof());

    // Debug
    libsnark::r1cs_ppzksnark_primary_input<ppT> primary_inputs = ext_proof.get_primary_input();
    display_primary_input<ppT>(primary_inputs);

    libff::leave_block("[END] Verify proof", true);

    return res;
}

bool Test_ValidJS1In1Out1PubVal(
    CircuitWrapper<1, 1> &prover,
    libsnark::r1cs_ppzksnark_keypair<ppT> keypair
) {
    // --- General setup for the tests --- //
    libff::print_header("Starting test (JS: 1 in, 1 out and 1 out pub val)");

    libff::enter_block("[START] General setup for the tests", true);

    // Create a merkle tree to run our tests
    // Note: make_unique should be C++14 compliant, but here we use c++11, so we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree<HashT>> test_merkle_tree = std::unique_ptr<libsnark::merkle_tree<HashT>>(
        new libsnark::merkle_tree<HashT>(
            ZETH_MERKLE_TREE_DEPTH,
            HashT::get_digest_len()
        )
    );
    std::ostream &stream = std::cout;
    libff::leave_block("[END] General setup for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1 -- //
    libff::enter_block("[BEGIN] Create JSInput", true);

    char* trap_r_str = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    bits384 trap_r_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector(trap_r_str));

    char* value_str = "2F0000000000000F";
    bits64 value_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_str));

    char* a_sk_str = "FF0000000000000000000000000000000000000000000000000000000000000F";
    bits256 a_sk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(a_sk_str));

    char* rho_str = "FFFF000000000000000000000000000000000000000000000000000000009009";
    bits256 rho_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(rho_str));

    char* rho_254_padded_with_01 = "8FFFC00000000000000000000000000000000000000000000000000000002402";

    char* a_pk_str = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b";
    bits256 a_pk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(a_pk_str));

    char* nf_str = "69f12603c2cfb2acf6f80a8f72cbdeb4417a6b8c7290e793c4d22830c4b35c5f";
    bits256 nf_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(nf_str));

    char* cm_str = "823d19485c94f74b4739ba7d17e4b434693086a996fa2e8d1438a91b1c220331";
    bits256 cm_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(cm_str));

    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;

    test_merkle_tree->set_value(address_commitment, libff::bit_vector(get_vector_from_bits256(cm_bits256)));
    libff::bit_vector updated_root_value = test_merkle_tree->get_root();
    std::vector<libsnark::merkle_authentication_node> path = test_merkle_tree->get_path(address_commitment);

    ZethNote note_input(
        a_pk_bits256,
        value_bits64,
        rho_bits256,
        trap_r_bits384
    );

    bitsAddr binary_address = get_bitsAddr_from_vector(address_bits);
    JSInput input(
        path,
        address_commitment,
        binary_address,
        note_input,
        a_sk_bits256,
        nf_bits256
    );

    std::array<JSInput, 1> inputs;
    inputs.fill(input);

    libff::leave_block("[END] Create JSInput", true);

    libff::enter_block("[BEGIN] Create JSOutput/ZethNote", true);

    char* value_str_out = "1800000000000008";
    bits64 value_out_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_str_out));

    char* a_pk_str_out = "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b";
    bits256 a_pk_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(a_pk_str_out));

    char* rho_out_str = "1111000000000000000000000000000000000000000000000000000000009777";
    bits256 rho_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(rho_out_str));

    char* trap_r_out_str = "11000000000000990000000000000099000000000000007700000000000000FF00000000000000FF0000000000000777";
    bits384 trap_r_out_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector(trap_r_out_str));

    ZethNote note_output(
        a_pk_out_bits256,
        value_out_bits64,
        rho_out_bits256,
        trap_r_out_bits384
    );

    char* value_pub_str_out = "1700000000000007";
    bits64 value_pub_out_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_pub_str_out));

    std::array<ZethNote, 1> outputs;
    outputs.fill(note_output);

    libff::leave_block("[END] Create JSOutput/ZethNote", true);

    libff::enter_block("[BEGIN] Generate proof", true);

    extended_proof<ppT> ext_proof = prover.prove(
        get_bits256_from_vector(updated_root_value),
        inputs,
        outputs,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")), // No value in here
        value_pub_out_bits64,
        keypair.pk
    );

    libff::leave_block("[END] Generate proof", true);

    libff::enter_block("[BEGIN] Verify proof", true);

    // Get the verification key
    libsnark::r1cs_ppzksnark_verification_key<ppT> vk = keypair.vk;
    bool res = libsnark::r1cs_ppzksnark_verifier_strong_IC<ppT>(vk, ext_proof.get_primary_input(), ext_proof.get_proof());

    libsnark::r1cs_ppzksnark_primary_input<ppT> primary_inputs = ext_proof.get_primary_input();
    display_primary_input<ppT>(primary_inputs);

    libff::leave_block("[END] Verify proof", true);

    return res;
}

bool Test_ValidJS2In2Out(
    CircuitWrapper<2, 2> &prover,
    libsnark::r1cs_ppzksnark_keypair<ppT> keypair
) {
    // --- General setup for the tests --- //
    libff::print_header("Starting test (JS: 2 in, 2 out and NO out pub val)");

    libff::enter_block("[START] General setup for the tests", true);

    // Create a merkle tree to run our tests
    // Note: make_unique should be C++14 compliant, but here we use c++11, so we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree<HashT>> test_merkle_tree = std::unique_ptr<libsnark::merkle_tree<HashT>>(
        new libsnark::merkle_tree<HashT>(
            ZETH_MERKLE_TREE_DEPTH,
            HashT::get_digest_len()
        )
    );
    std::ostream &stream = std::cout;
    libff::leave_block("[END] General setup for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1 -- //
    libff::enter_block("[BEGIN] Create JSInput", true);

    char* trap_r_str = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    bits384 trap_r_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector(trap_r_str));

    char* value_str = "2F0000000000000F";
    bits64 value_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_str));

    char* a_sk_str = "FF0000000000000000000000000000000000000000000000000000000000000F";
    bits256 a_sk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(a_sk_str));

    char* rho_str = "FFFF000000000000000000000000000000000000000000000000000000009009";
    bits256 rho_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(rho_str));

    char* rho_254_padded_with_01 = "8FFFC00000000000000000000000000000000000000000000000000000002402";

    char* a_pk_str = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b";
    bits256 a_pk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(a_pk_str));

    char* nf_str = "69f12603c2cfb2acf6f80a8f72cbdeb4417a6b8c7290e793c4d22830c4b35c5f";
    bits256 nf_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(nf_str));

    char* cm_str = "823d19485c94f74b4739ba7d17e4b434693086a996fa2e8d1438a91b1c220331";
    bits256 cm_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(cm_str));

    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;

    test_merkle_tree->set_value(address_commitment, libff::bit_vector(get_vector_from_bits256(cm_bits256)));
    libff::bit_vector updated_root_value = test_merkle_tree->get_root();
    std::vector<libsnark::merkle_authentication_node> path = test_merkle_tree->get_path(address_commitment);

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

    JSInput input(
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
    JSInput input_dummy(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_dummy_input,
        a_sk_bits256,
        nf_bits256
    );

    std::array<JSInput, 2> inputs;
    inputs[0] = input;
    inputs[1] = input_dummy;

    libff::leave_block("[END] Create JSInput", true);

    libff::enter_block("[BEGIN] Create JSOutput/ZethNote", true);

    char* value_str_out = "1800000000000008";
    bits64 value_out_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_str_out));

    char* a_pk_str_out = "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b";
    bits256 a_pk_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(a_pk_str_out));

    char* rho_out_str = "1111000000000000000000000000000000000000000000000000000000009777";
    bits256 rho_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(rho_out_str));

    char* trap_r_out_str = "11000000000000990000000000000099000000000000007700000000000000FF00000000000000FF0000000000000777";
    bits384 trap_r_out_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector(trap_r_out_str));

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

    char* value_pub_str_out = "1700000000000007";
    bits64 value_pub_out_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_pub_str_out));

    std::array<ZethNote, 2> outputs;
    outputs[0] = note_output;
    outputs[1] = note_dummy_output;

    libff::leave_block("[END] Create JSOutput/ZethNote", true);

    libff::enter_block("[BEGIN] Generate proof", true);

    auto start_proof = std::chrono::high_resolution_clock::now();
    extended_proof<ppT> ext_proof = prover.prove(
        get_bits256_from_vector(updated_root_value),
        inputs,
        outputs,
        get_bits64_from_vector(hexadecimal_str_to_binary_vector("0000000000000000")), // No value in here
        value_pub_out_bits64,
        keypair.pk
    );
    auto stop_proof = std::chrono::high_resolution_clock::now();

    libff::leave_block("[END] Generate proof", true);

    libff::enter_block("[BEGIN] Verify proof", true);

    // Get the verification key
    libsnark::r1cs_ppzksnark_verification_key<ppT> vk = keypair.vk;
    auto verif_start = std::chrono::high_resolution_clock::now();
    bool res = libsnark::r1cs_ppzksnark_verifier_strong_IC<ppT>(vk, ext_proof.get_primary_input(), ext_proof.get_proof());
    auto verif_stop = std::chrono::high_resolution_clock::now();

    libsnark::r1cs_ppzksnark_primary_input<ppT> primary_inputs = ext_proof.get_primary_input();
    display_primary_input<ppT>(primary_inputs);

    libff::leave_block("[END] Verify proof", true);

    std::cout << " ========= Perfs results: ========= " << std::endl;
    auto proof_duration = std::chrono::duration_cast<std::chrono::microseconds>(stop_proof - start_proof);
    auto verif_duration = std::chrono::duration_cast<std::chrono::microseconds>(verif_stop - verif_start);
    std::cout << "Time taken by prove function: " << proof_duration.count() << " microseconds" << std::endl; 
    std::cout << "Time taken by verify function: " << verif_duration.count() << " microseconds" << std::endl; 

    return res;
}

TEST(MainTests, ProofGenAndVerifJS1to1) {
    // Run the trusted setup once for all tests, and keep the keypair in memory for the duration of the tests
    CircuitWrapper<1, 1> proverJS1to1;
    libsnark::r1cs_ppzksnark_keypair<ppT> keypair = proverJS1to1.generate_trusted_setup();
    bool res = false;

    res = Test_ValidJS1In1Out(proverJS1to1, keypair);
    std::cout << "[ProofGenAndVerifJS1to1] Test 1" << std::endl;
    ASSERT_TRUE(res);

    try {
        res = Test_InvalidJS1In1Out(proverJS1to1, keypair);
        std::cout << "[ProofGenAndVerifJS1to1] Test 2" << std::endl;
        ASSERT_FALSE(res);
    } catch (const std::invalid_argument& ia) {
        std::cerr << "[Joinsplit balance constraint violated: Error thrown and proof generation aborted]: " << ia.what() << '\n';
    }

    res = Test_ValidJS1In1Out1PubVal(proverJS1to1, keypair);
    std::cout << "[ProofGenAndVerifJS1to1] Test 3" << std::endl;
    ASSERT_TRUE(res);
}

TEST(MainTests, ProofGenAndVerifJS2to2) {
    // Run the trusted setup once for all tests, and keep the keypair in memory for the duration of the tests
    CircuitWrapper<2, 2> proverJS2to2;
    libsnark::r1cs_ppzksnark_keypair<ppT> keypair = proverJS2to2.generate_trusted_setup();
    bool res = false;

    res = Test_ValidJS2In2Out(proverJS2to2, keypair);
    std::cout << "[ProofGenAndVerifJS2to2] Test 1" << std::endl;
    ASSERT_TRUE(res);
}

} // namespace

int main(int argc, char **argv) {
    ppT::init_public_params(); // /!\ WARNING: Do once for all tests. Do not forget to do this !!!!
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}