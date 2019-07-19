#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure
#include "src/types/merkle_tree.hpp"

// Header to use the sha256_ethereum gadget
#include "circuits/sha256/sha256_ethereum.hpp"

// Access the `from_bits` function and other utils
#include "circuits/circuits-util.hpp"
#include "util.hpp"

// Access the defined constants
#include "zeth.h"

// Bring the types in scope
#include "types/bits.hpp"
#include "types/note.hpp"

// Gadget to test
#include "circuits/notes/note.hpp"

using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT; // Should be alt_bn128 in the CMakeLists.txt
typedef sha256_ethereum<FieldT> HashT; // We use our hash function to do the tests
typedef MiMC_hash_gadget<FieldT> HashTreeT; // We use our hash function to do the tests


namespace {

TEST(TestNoteCircuits, TestInputNoteGadget) {
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb);
    pb.val(ZERO) = FieldT::zero();

    std::ostream &stream = std::cout;

    libff::enter_block("[BEGIN] Initialize the coins' data (nullifier, a_sk and a_pk, cm, rho)", true);
    bits384 trap_r_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector("0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF"));
    bits64 value_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector("2F0000000000000F"));
    bits256 a_sk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("FF0000000000000000000000000000000000000000000000000000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("FFFF000000000000000000000000000000000000000000000000000000009009"));

    // Get a_pk from a_sk (PRF)
    //
    // a_sk = 0xFF0000000000000000000000000000000000000000000000000000000000000F
    // 0^256 = 0x0000000000000000000000000000000000000000000000000000000000000000
    // a_pk = sha256(a_sk || 0^256)
    // Generated directly from a_sk and solidity sha256 (solidity v0.5.0)
    bits256 a_pk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"));

    // Get nf from a_sk and rho (PRF)
    //
    // nf = sha256(a_sk || 01 || [rho]_254)
    // a_sk: 0xFF0000000000000000000000000000000000000000000000000000000000000F
    // '01 || [rho]_254' = 0x8FFFC00000000000000000000000000000000000000000000000000000002402
    // The test vector generated directly from a_sk and solidity sha256 (solidity v0.5.0), gives:
    // nf = 0x69f12603c2cfb2acf6f80a8f72cbdeb4417a6b8c7290e793c4d22830c4b35c5f
    bits256 nf_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("69f12603c2cfb2acf6f80a8f72cbdeb4417a6b8c7290e793c4d22830c4b35c5f"));

    // Get the coin's commitment (COMM)
    //
    // inner_k = sha256(a_pk || rho)
    // outer_k = sha256(r || [inner_commitment]_128)
    // cm = sha256(outer_k || 0^192 || value_v)
    bits256 cm_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("823d19485c94f74b4739ba7d17e4b434693086a996fa2e8d1438a91b1c220331"));
    FieldT cm_field = FieldT("19887018545733584132694987702455052448105722733816648703966348992317566270527");
    libff::leave_block("[END] Initialize the coins' data (nullifier, a_sk and a_pk, cm, rho)", true);

    libff::enter_block("[BEGIN] Setup a local merkle tree and append our commitment to it", true);
    
    std::unique_ptr<merkle_tree<FieldT, HashTreeT>> test_merkle_tree = std::unique_ptr<merkle_tree<FieldT, HashTreeT>>(
        new merkle_tree<FieldT, HashTreeT>(
            ZETH_MERKLE_TREE_DEPTH
        )
    );

    // In practice the address is emitted by the mixer contract once the commitment is appended to the tree
    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;
    test_merkle_tree->set_value(address_commitment, cm_field);

    // Get the root of the new/non-empty tree (after insertion)
    FieldT updated_root_value = test_merkle_tree->get_root();
    libff::leave_block("[END] Setup a local merkle tree and append our commitment to it", true);

    libff::enter_block("[BEGIN] Data conversion to generate a witness of the note gadget", true);
    std::shared_ptr<libsnark::digest_variable<FieldT> > nullifier_digest;
    nullifier_digest.reset(new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), "nullifier_digest"));
    nullifier_digest->generate_r1cs_constraints();
    nullifier_digest->generate_r1cs_witness(libff::bit_vector(get_vector_from_bits256(nf_bits256)));

    std::cout <<  "nullifier done, defining merkle root"<< updated_root_value << std::endl;
    std::shared_ptr<libsnark::pb_variable<FieldT> > merkle_root;
    merkle_root.reset(new libsnark::pb_variable<FieldT>);
    (*merkle_root).allocate(pb, "root");
    pb.val(*merkle_root) = updated_root_value;

    std::cout << "initialising input node" << std::endl;
    std::shared_ptr<input_note_gadget<HashTreeT, FieldT>> input_note_g  = std::shared_ptr<input_note_gadget<HashTreeT, FieldT>>(
        new input_note_gadget<HashTreeT, FieldT>(
            pb,
            ZERO,
            nullifier_digest,
            *merkle_root
        )
    );

    // Get the merkle path to the commitment we appended
    std::cout << "getting path" << std::endl;
    std::vector<FieldT> path = test_merkle_tree->get_path(address_commitment);

    // Create a note from the coin's data
    std::cout <<  "making znote" << std::endl;
    ZethNote note(
        a_pk_bits256, 
        value_bits64, 
        rho_bits256, 
        trap_r_bits384
    );

    std::cout <<  "calling input note constraints" << std::endl;
    input_note_g->generate_r1cs_constraints();

    std::cout <<  "calling input note witness" << std::endl;
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

TEST(TestNoteCircuits, TestOutputNoteGadget) {
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb);
    pb.val(ZERO) = FieldT::zero();

    std::ostream &stream = std::cout;

    libff::enter_block("[BEGIN] Initialize the output coins' data (a_pk, cm, rho)", true);
    bits384 trap_r_bits384 = get_bits384_from_vector(hexadecimal_str_to_binary_vector("0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF"));
    bits64 value_bits64 = get_bits64_from_vector(hexadecimal_str_to_binary_vector("2F0000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("FFFF000000000000000000000000000000000000000000000000000000009009"));
    bits256 a_pk_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"));

    // Get the coin's commitment (COMM)
    //
    // inner_k = sha256(a_pk || rho)
    // outer_k = sha256(r || [inner_commitment]_128)
    // cm = sha256(outer_k || 0^192 || value_v)
    bits256 cm_bits256 = get_bits256_from_vector(hexadecimal_digest_to_binary_vector("823d19485c94f74b4739ba7d17e4b434693086a996fa2e8d1438a91b1c220331"));
    libff::leave_block("[END] Initialize the output coins' data (a_pk, cm, rho)", true);

    libff::enter_block("[BEGIN] Data conversion to generate a witness of the note gadget", true);
    std::shared_ptr<libsnark::digest_variable<FieldT> > commitment;
    commitment.reset(new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), "root_digest"));
    std::shared_ptr<output_note_gadget<FieldT>> output_note_g  = std::shared_ptr<output_note_gadget<FieldT>>(
        new output_note_gadget<FieldT>(
            pb,
            ZERO,
            commitment
        )
    );

    // Create a note from the coin's data
    ZethNote note(
        a_pk_bits256, 
        value_bits64, 
        rho_bits256, 
        trap_r_bits384
    );

    output_note_g->generate_r1cs_constraints();
    output_note_g->generate_r1cs_witness(
        note
    );
    libff::leave_block("[END] Data conversion to generate a witness of the note gadget", true);

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "************* SAT result: " << is_valid_witness <<  " ******************" << std::endl;
    ASSERT_TRUE(is_valid_witness);

    // Last check to make sure the commitment computed is the expected one
    libff::bit_vector obtained_digest = commitment->get_digest();
    libff::bit_vector expected_digest = libff::bit_vector(get_vector_from_bits256(cm_bits256));
    ASSERT_EQ(obtained_digest, expected_digest);
};

} // namespace

int main(int argc, char **argv) {
    ppT::init_public_params(); // /!\ WARNING: Do once for all tests. Do not forget to do this !!!!
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}