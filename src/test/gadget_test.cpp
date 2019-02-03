#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Header to use the sha256_ethereum gadget
#include "sha256_ethereum.hpp"

#include "util.hpp"

// Access the defined constants
#include "zeth.h"

// Include the type we need
#include "bits256.tcc"
#include "joinsplit.hpp"
#include "note.hpp"

// Gadgets to test
#include "gadget.tcc"

using namespace libzeth;

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

TEST(TestMainCircuit, TestMainGadget) {
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb);
    pb.val(ZERO) = FieldT::zero();

    // We test a JoinSplit with only 1 input and 1 output (and no v_pub value)
    joinsplit_gadget<FieldT, HashT, 1, 1> js_gadget(pb);

    // Generate the constraints
    js_gadget->generate_r1cs_constraints();

    // Create the input witness
    libff::enter_block("[BEGIN] Create JSInput", true);
    // trap_r: 384 bits
    // hex: 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF
    char* trap_r_str = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    bits384 trap_r_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector(trap_r_str));

    // 64 bits for the value
    // hex: 0x2F0000000000000F
    char* value_str = "2F0000000000000F";
    bits64 value_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_str));

    // hex: 0xFF0000000000000000000000000000000000000000000000000000000000000F
    char* a_sk_str = "FF0000000000000000000000000000000000000000000000000000000000000F";
    bits256 a_sk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(a_sk_str));

    // hex: 0xFFFF000000000000000000000000000000000000000000000000000000009009
    char* rho_str = "FFFF000000000000000000000000000000000000000000000000000000009009";
    bits256 rho_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(rho_str));

    // hex: 0x8FFFC00000000000000000000000000000000000000000000000000000002402
    char* rho_254_padded_with_01 = "8FFFC00000000000000000000000000000000000000000000000000000002402";

    // Get a_pk from a_sk (PRF)
    //
    // a_sk = 0xFF0000000000000000000000000000000000000000000000000000000000000F
    // 0^256 = 0x0000000000000000000000000000000000000000000000000000000000000000
    // a_pk = sha256(a_sk || 0^256)
    // Generated directly from a_sk and solidity sha256 (solidity v0.5.0)
    char* a_pk_str = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b";
    bits256 a_pk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(a_pk_str));

    // Get nf from a_sk and rho (PRF)
    //
    // nf = sha256(a_sk || 01 || [rho]_254)
    // a_sk: 0xFF0000000000000000000000000000000000000000000000000000000000000F
    // '01 || [rho]_254' = 0x8FFFC00000000000000000000000000000000000000000000000000000002402
    // The test vector generated directly from a_sk and solidity sha256 (solidity v0.5.0), gives:
    // nf = 0x69f12603c2cfb2acf6f80a8f72cbdeb4417a6b8c7290e793c4d22830c4b35c5f
    char* nf_str = "69f12603c2cfb2acf6f80a8f72cbdeb4417a6b8c7290e793c4d22830c4b35c5f";
    bits256 nf_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(nf_str));

    // Get the coin's commitment (COMM)
    //
    // inner_k = sha256(a_pk || rho)
    char* inner_k_str = "c8064b9113f19c058aa0295a88fd79c096eb2b9553f95af0c9c7b322448e8446";
    // outer_k = sha256(r || [inner_commitment]_128)
    char* inner_k_str_first_128_bits = "c8064b9113f19c058aa0295a88fd79c0";
    char* outer_k_str = "806e5c213a2f3d436273e924eb6311ac2db6c33624b28165b79c779e00fa2752";
    // cm = sha256(outer_k || 0^192 || value_v)
    char* value_front_padded_zeroes = "0000000000000000000000000000000000000000000000002F0000000000000F";
    char* cm_str = "823d19485c94f74b4739ba7d17e4b434693086a996fa2e8d1438a91b1c220331";
    bits256 cm_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(cm_str));

    // Get the merkle root
    std::unique_ptr<libsnark::merkle_tree<HashT>> test_merkle_tree = std::unique_ptr<libsnark::merkle_tree<HashT>>(
        new libsnark::merkle_tree<HashT>(
            ZETH_MERKLE_TREE_DEPTH,
            HashT::get_digest_len()
        )
    );
    // In practice the address is emitted by the mixer contract once the commitment is appended to the tree
    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;
    test_merkle_tree->set_value(address_commitment, libff::bit_vector(get_vector_from_bits256(cm_bits256)));
    // Get the root of the new/non-empty tree (after insertion)
    libff::bit_vector updated_root_value = test_merkle_tree->get_root();

    // Get the merkle path
    std::vector<libsnark::merkle_authentication_node> path = test_merkle_tree->get_path(address_commitment);

    ZethNote note_input(
        a_pk_bits256,
        value_bits64,
        rho_bits256,
        trap_r_bits384,
        cm_bits256
    );

    JSInput input(
        path,
        address_commitment,
        address_bits,
        note_input,
        a_sk_bits256,
        nf_bits256
    );

    std::array<JSInput, 1> inputs;
    inputs.fill(input);

    libff::leave_block("[END] Create JSInput", true);

    libff::enter_block("[BEGIN] Create JSOutput/ZethNote", true);

    // Here we make sure the value of the zeth note that is an output of the JS equals the value of the input
    // as we want this proof to be correctly verified
    char* value_str_out = "2F0000000000000F";
    bits64 value_out_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_str_out));

    char* a_pk_str_out = "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b";
    bits256 a_pk_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(a_pk_str_out));

    char* rho_out_str = "1111000000000000000000000000000000000000000000000000000000009777";
    bits256 rho_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(rho_out_str));

    char* trap_r_out_str = "11000000000000990000000000000099000000000000007700000000000000FF00000000000000FF0000000000000777";
    bits384 trap_r_out_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector(trap_r_out_str));

    // inner_k = sha256(a_pk || rho)
    char* inner_k_str_out = "59f8b7f7bcbc492e4d9f96517e75ad1fc675dfb600bfae3ee53b79adb8c392fd";
    // outer_k = sha256(r || [inner_commitment]_128)
    char* inner_k_str_first_128_bits_out = "59f8b7f7bcbc492e4d9f96517e75ad1f";
    char* outer_k_str_out = "13a067be67971e25bf9e46fb93bb98b91619aba6c383cfcc803d70527a6ba04d";
    // cm = sha256(outer_k || 0^192 || value_v)
    char* value_front_padded_zeroes_out = "0000000000000000000000000000000000000000000000002F0000000000000F";
    char* cm_str_out = "f23084ce25a5844abdae214896d13c376a9aea4bfe4cafbb5572822feb39b8ea";
    bits256 cm_out_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector(cm_str_out));

    ZethNote note_output(
        a_pk_out_bits256,
        value_out_bits64,
        rho_out_bits256,
        trap_r_out_bits384,
        cm_out_bits256
    );

    char* value_pub_str_out = "0000000000000000";
    bits64 value_pub_out_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector(value_pub_str_out));

    std::array<ZethNote, 1> outputs;
    outputs.fill(note_output);

    libff::leave_block("[END] Create JSOutput/ZethNote", true);

    libff::enter_block("[BEGIN] Generate witness", true);
    // Generate the constraints
    js_gadget->generate_r1cs_witness();
    libff::leave_block("[END] Generate witness", true);

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "************* SAT result: " << is_valid_witness <<  " ******************" << std::endl;

    ASSERT_TRUE(is_valid_witness);
};

} // namespace

int main(int argc, char **argv) {
    ppT::init_public_params(); // /!\ WARNING: Do once for all tests. Do not forget to do this !!!!
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}