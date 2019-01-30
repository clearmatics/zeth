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

// Use the bits256 type util functions
#include "bits256.tcc"

// Gadgets to test
#include "note.hpp"
#include "note.tcc"

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

TEST(TestNoteCircuits, TestInputNoteGadget) {
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb);
    pb.val(ZERO) = FieldT::zero();

    std::ostream &stream = std::cout;

    libff::enter_block("[BEGIN] Initialize the coins' data (nullifier, a_sk and a_pk, cm, rho)", true);

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

    /*
     *
     * At that point we have a coin with data:
     * - value = 0x2F0000000000000F
     * - trap_r = 0x0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF
     * - a_pk = 0x6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b
     * - a_sk = 0xFF0000000000000000000000000000000000000000000000000000000000000F
     * - commitment_k = 0x806e5c213a2f3d436273e924eb6311ac2db6c33624b28165b79c779e00fa2752
     * - commitment_cm = 0x823d19485c94f74b4739ba7d17e4b434693086a996fa2e8d1438a91b1c220331
     * 
    **/
   libff::leave_block("[END] Initialize the coins' data (nullifier, a_sk and a_pk, cm, rho)", true);

   libff::enter_block("[BEGIN] Setup a local merkle tree and append our commitment to it", true);
    std::unique_ptr<libsnark::merkle_tree<HashT>> test_merkle_tree = std::unique_ptr<libsnark::merkle_tree<HashT>>(
        new libsnark::merkle_tree<HashT>(
            ZETH_MERKLE_TREE_DEPTH,
            HashT::get_digest_len()
        )
    );

    // Check the root of the empty tree (for debug purpose/before insertion)
    libff::bit_vector initial_root_value = test_merkle_tree->get_root();

    // In practice the address is emitted by the mixer contract once the commitment is appended to the tree
    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;
    test_merkle_tree->set_value(address_commitment, libff::bit_vector(get_vector_from_bits256(cm_bits256)));

    // Get the root of the new/non-empty tree (after insertion)
    libff::bit_vector updated_root_value = test_merkle_tree->get_root();

    std::cout << "=== [DEBUG] Root before insertion bit representation: " << std::endl;
    dump_bit_vector(stream, initial_root_value);
    std::cout << "=== [DEBUG] Root after insertion bit representation: " << std::endl;
    dump_bit_vector(stream, updated_root_value);

    libff::leave_block("[END] Setup a local merkle tree and append our commitment to it", true);

    libff::enter_block("[BEGIN] Data conversion to generate a witness of the note gadget", true);
    std::shared_ptr<libsnark::digest_variable<FieldT> > nullifier_digest;
    nullifier_digest.reset(new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), "nullifier_digest"));
    nullifier_digest->generate_r1cs_constraints();
    nullifier_digest->generate_r1cs_witness(libff::bit_vector(get_vector_from_bits256(nf_bits256)));

    std::shared_ptr<libsnark::digest_variable<FieldT> > root_digest;
    root_digest.reset(new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), "root_digest"));
    root_digest->generate_r1cs_constraints();
    root_digest->generate_r1cs_witness(libff::bit_vector(updated_root_value));
    std::shared_ptr<input_note_gadget<FieldT>> input_note_g  = std::shared_ptr<input_note_gadget<FieldT>>(
        new input_note_gadget<FieldT>(
            pb,
            ZERO,
            nullifier_digest,
            *root_digest
        )
    );

    // Get the merkle path to the commitment we appended
    std::vector<libsnark::merkle_authentication_node> path = test_merkle_tree->get_path(address_commitment);

    // Create a note from the coin's data
    ZethNote note(
        a_pk_bits256, 
        value_bits64, 
        rho_bits256, 
        trap_r_bits384, 
        cm_bits256
    );

    input_note_g->generate_r1cs_constraints();
    input_note_g->generate_r1cs_witness(
        path,
        address_commitment,
        address_bits,
        a_sk_bits256,
        note
    );
    libff::leave_block("[END] Data conversion to generate a witness of the note gadget", true);

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