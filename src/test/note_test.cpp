#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure
#include "src/types/merkle_tree.hpp"

// Access the defined constants
#include "zeth.h"

// Bring the types in scope
#include "types/note.hpp"

// Gadget to test
#include "circuits/notes/note.hpp"

#include "circuits/mimc/mimc_hash.hpp"
#include "snarks_alias.hpp"



using namespace libzeth;
using namespace libsnark;

typedef MiMC_hash_gadget<FieldT> HashT;
typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT; // Should be alt_bn128 in the CMakeLists.txt

namespace {

TEST(TestNoteCircuits, TestInputNoteGadget) {
    libsnark::protoboard<FieldT> pb;
    std::ostream &stream = std::cout;



    libff::enter_block("[BEGIN] Initialize the coins' data (nullifier, a_sk and a_pk, cm, rho)", true);
    // Let's choose a_sk = mimc_hash([0], sha3("Clearmatics"))
    FieldT a_sk = FieldT("18834251028175908666459239027856614524890385928194459012149074634190864282942");
    // a_pk = mimc_hash([a_sk, 0], sha3("Clearmatics_add"))
    // We could perhaps drop the "0" or consider several pk for the same sk
    FieldT a_pk = FieldT("7557284417121959865806721773315070721481656811910187747772194493889443679515");

    // Let's choose r_trap = mimc_hash([1], sha3("Clearmatics")) and r_mask = mimc_hash([2], sha3("Clearmatics"))
    FieldT r_trap = FieldT("6576838732374919021860119342200398901974877797242970520445052250557344565821"); 
    FieldT r_mask = FieldT("12946791413528024759839394340318236878559158148001437182189040772047964059643"); 

     // Let's choose rho = mimc_hash([3], sha3("Clearmatics"))
    FieldT rho = FieldT("1050857222747641138499486657636501128934992461797459043826425853190223953952");
    // nf = mimc_hash([a_sk, rho], sha3("Clearmatics_sn"))
    FieldT nf = FieldT("16718990446402804328289195783834079890551903281540894658644001381677667818395");

    FieldT value = FieldT("100");

    // inner_k = mimc_hash(a_pk, rho)
    FieldT inner_k = FieldT("7525462055068850756704202737069719250735251830112288124323778368808523240623");
    // outer_k = mimc_hash(r_trap, masked) with masked = inner_k +r_mask
    // masked = 20472253468596875516543597077387956129294409978113725306512819140856487300266
    FieldT outer_k = FieldT("18303545575895747902094842552645262963308975351435684613898377861780805247602");
    // cm = mimc_hash(outer_k, value_v)
    FieldT cm = FieldT("21075862836612025410946586494502715375244302209109240154340545056954086062438");
    libff::leave_block("[END] Initialize the coins' data (nullifier, a_sk and a_pk, cm, rho)", true);



    libff::enter_block("[BEGIN] Setup a local merkle tree and append our commitment to it", true);

    merkle_tree<FieldT, HashT> mtree = merkle_tree<FieldT, HashT>(ZETH_MERKLE_TREE_DEPTH);

    std::unique_ptr<merkle_tree<FieldT, HashT>> test_merkle_tree = std::unique_ptr<merkle_tree<FieldT, HashT>>(
        new merkle_tree<FieldT, HashT>(
            ZETH_MERKLE_TREE_DEPTH
        )
    );

    // In practice the address is emitted by the mixer contract once the commitment is appended to the tree
    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;
    test_merkle_tree->set_value(address_commitment, cm);

    // Get the root of the new/non-empty tree (after insertion)
    FieldT updated_root_value = test_merkle_tree->get_root();
    libff::leave_block("[END] Setup a local merkle tree and append our commitment to it", true);



    libff::enter_block("[BEGIN] Data conversion to generate a witness of the note gadget", true);
    std::shared_ptr<libsnark::pb_variable<FieldT> > nullifier_digest;
    nullifier_digest.reset(new libsnark::pb_variable<FieldT>);
    (*nullifier_digest).allocate(pb, "nf");

    std::shared_ptr<libsnark::pb_variable<FieldT>> root_digest;
    root_digest.reset(new libsnark::pb_variable<FieldT>);
    (*root_digest).allocate(pb, "root");
    pb.val(*root_digest) = updated_root_value;

    std::shared_ptr<input_note_gadget<HashT, FieldT>> input_note_g  = std::shared_ptr<input_note_gadget<HashT, FieldT>>(
        new input_note_gadget<HashT, FieldT>(
            pb,
            nullifier_digest,
            *root_digest
        )
    );
    std::cout << "root digest: " << updated_root_value << std::endl;

    // Get the merkle path to the commitment we appended
    std::vector<FieldT> path_values = test_merkle_tree->get_path(address_commitment);

    // Create a note from the coin's data
    ZethNote<FieldT> note(
        a_pk, 
        value, 
        rho, 
        r_trap,
        r_mask
    );

    input_note_g->generate_r1cs_constraints();
    input_note_g->generate_r1cs_witness(
        path_values,
        address_bits,
        a_sk,
        note
    );
    libff::leave_block("[END] Data conversion to generate a witness of the note gadget", true);

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "************* SAT result: " << is_valid_witness <<  " ******************" << std::endl;

    ASSERT_TRUE(is_valid_witness);
};

TEST(TestNoteCircuits, TestOutputNoteGadget) {
    libsnark::protoboard<FieldT> pb;
    std::ostream &stream = std::cout;



    libff::enter_block("[BEGIN] Initialize the output coins' data (a_pk, cm, rho)", true);
    // Let's choose a_sk = mimc_hash([0], sha3("Clearmatics"))
    FieldT a_sk = FieldT("18834251028175908666459239027856614524890385928194459012149074634190864282942");
    // a_pk = mimc_hash([a_sk, 0], sha3("Clearmatics_add"))
    // We could perhaps drop the "0" or consider several pk for the same sk
    FieldT a_pk = FieldT("7557284417121959865806721773315070721481656811910187747772194493889443679515");

    // Let's choose r_trap = mimc_hash([1], sha3("Clearmatics")) and r_mask = mimc_hash([2], sha3("Clearmatics"))
    FieldT r_trap = FieldT("6576838732374919021860119342200398901974877797242970520445052250557344565821"); 
    FieldT r_mask = FieldT("12946791413528024759839394340318236878559158148001437182189040772047964059643"); 

     // Let's choose rho = mimc_hash([3], sha3("Clearmatics"))
    FieldT rho = FieldT("1050857222747641138499486657636501128934992461797459043826425853190223953952");
    // nf = mimc_hash([a_sk, rho], sha3("Clearmatics_sn"))
    FieldT nf = FieldT("16718990446402804328289195783834079890551903281540894658644001381677667818395");

    FieldT value = FieldT("100");

    // inner_k = mimc_hash(a_pk, rho)
    FieldT inner_k = FieldT("7525462055068850756704202737069719250735251830112288124323778368808523240623");
    // outer_k = mimc_hash(r_trap, masked) with masked = inner_k +r_mask
    // masked = 20472253468596875516543597077387956129294409978113725306512819140856487300266
    FieldT outer_k = FieldT("18303545575895747902094842552645262963308975351435684613898377861780805247602");
    // cm = mimc_hash(outer_k, value_v)
    FieldT cm = FieldT("21075862836612025410946586494502715375244302209109240154340545056954086062438");
    libff::leave_block("[END] Initialize the output coins' data (a_pk, cm, rho)", true);



    libff::enter_block("[BEGIN] Data conversion to generate a witness of the note gadget", true);
    std::shared_ptr<libsnark::pb_variable<FieldT> > commitment;
    commitment.reset(new libsnark::pb_variable<FieldT>);
    (*commitment).allocate(pb, "cm");

    std::shared_ptr<output_note_gadget<FieldT>> output_note_g  = std::shared_ptr<output_note_gadget<FieldT>>(
        new output_note_gadget<FieldT>(
            pb,
            commitment
        )
    );

    // Create a note from the coin's data
    ZethNote<FieldT> note(
        a_pk, 
        value, 
        rho, 
        r_trap,
        r_mask
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
    ASSERT_EQ(pb.val((*output_note_g).get_cm()), cm);
};

} // namespace

int main(int argc, char **argv) {
    ppT::init_public_params(); // /!\ WARNING: Do once for all tests. Do not forget to do this !!!!
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}