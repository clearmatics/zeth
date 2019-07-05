#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure to keep a local merkle tree
#include <src/types/merkle_tree.hpp> //<libsnark/common/data_structures/merkle_tree.hpp>

// Have access to a chrono to measure the rough time of execution of a set of instructions
#include <chrono>
#include "snarks_alias.hpp"
// Import only the core components of the SNARK (not the API components)
#include "snarks_core_imports.hpp"
#include "libsnark_helpers/libsnark_helpers.hpp"
#include "circuits/mimc/mimc_hash.hpp" //"circuits/sha256/sha256_ethereum.hpp"
#include "circuit-wrapper.hpp"
#include "util.hpp"

using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT; // Should be alt_bn128 in the CMakeLists.txt
typedef MiMC_hash_gadget<FieldT> HashT; // We use our hash function to do the tests

namespace {

bool TestValidJS2In2Case1(
    CircuitWrapper<FieldT, HashT, 2, 2> &prover,
    libzeth::keyPairT<ppT> keypair
) {
    // --- General setup for the tests --- //
    libff::print_header("test JS 2-2: IN => vpub_in = 0, note1 = 100, note2 =x0 || OUT => vpub_out = 25, note1 = 75, note2 = 0");

    libff::enter_block("[START] Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    // Note: `make_unique` should be C++14 compliant, but here we use c++11, so we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree<FieldT, HashT>> test_merkle_tree = std::unique_ptr<merkle_tree<FieldT, HashT>>(
        new merkle_tree<FieldT, HashT>(
            ZETH_MERKLE_TREE_DEPTH
        )
    );
    libff::leave_block("[END] Instantiate merkle tree for the tests", true);



    // --- Test 1: Generate a valid proof for commitment inserted at address 1 -- //
    libff::enter_block("[BEGIN] Create JSInput", true);
    // Create the zeth note data for the commitment we will insert in the tree (commitment to spend in this test)
    FieldT r_trap = FieldT("6576838732374919021860119342200398901974877797242970520445052250557344565821");
    FieldT a_sk = FieldT("18834251028175908666459239027856614524890385928194459012149074634190864282942");
    FieldT a_pk = FieldT("5387907419355715653531038695566357046482139005118304712469340438697294642611");
    FieldT rho = FieldT("12946791413528024759839394340318236878559158148001437182189040772047964059643");
    FieldT nf = FieldT("11936680607858084380537967489495552519299143216151535029075478675240592155294");
    FieldT value = FieldT("100");
    FieldT cm = FieldT("7696443061196341087326334761452156208417519921123230974759309762690342959594");
    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm);
    FieldT updated_root_value = test_merkle_tree->get_root();
    //std::vector<libsnark::merkle_authentication_node> path = test_merkle_tree->get_path(address_commitment);
    std::vector<FieldT> path = test_merkle_tree->get_path(address_commitment);

   ZethNote<FieldT> note_input(
        a_pk,
        value,
        rho,
        r_trap
    );

    ZethNote<FieldT> note_dummy_input(
        a_pk,
        FieldT("0"),
        FieldT("6845108050456603036310667214894676007661663921399154479307840696887919990996"),  // rho_dummy = mimic_hash([4], sha3("Clearmatics"))
        r_trap
    );

    JSInput<FieldT> input(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input,
        a_sk,
        nf
    );

    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path check
    // Doesn't count in such case
    JSInput<FieldT> input_dummy(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_dummy_input,
        a_sk,
        nf
    );


    std::array<JSInput<FieldT>, 2> inputs;
    inputs[0] = input;
    inputs[1] = input_dummy;
    libff::leave_block("[END] Create JSInput", true);



    libff::enter_block("[BEGIN] Create JSOutput/ZethNote", true);

    FieldT a_sk_out = FieldT("4047591473000155590199171927915978796573140621771266280705379796913645161555"); // mimic_hash([-1], sha3("Clearmatics"))
    FieldT a_pk_out = FieldT("5040863357084416281938805346896392895336796766724344426662331268783559604278");
    FieldT r_trap_out = FieldT("3121287842287349864642297846963883646477840388236905026425392648441319037621"); // mimic_hash([-2], sha3("Clearmatics"))
    FieldT rho_out = FieldT("10448869983030339500740742410361707713409326656173533049846269061232406471931"); // mimic_hash([-4], sha3("Clearmatics"))
    FieldT value_out = FieldT("75");

   ZethNote<FieldT> note_output(
        a_pk_out,
        value_out,
        rho_out,
        r_trap_out
    );

    ZethNote<FieldT> note_dummy_output(
        a_pk_out,
        FieldT("0"),
        rho_out,
        r_trap_out
    );
    std::array<ZethNote<FieldT>, 2> outputs;
    outputs[0] = note_output;
    outputs[1] = note_dummy_output;

    FieldT value_pub_out = FieldT("25");

    libff::leave_block("[END] Create JSOutput/ZethNote", true);



    libff::enter_block("[BEGIN] Generate proof", true);
    extended_proof<ppT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        FieldT("0"), // vpub_in = 0
        value_pub_out,
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
    CircuitWrapper<FieldT, HashT, 2, 2> &prover,
    libzeth::keyPairT<ppT> keypair
) {
    libff::print_header("Starting test: IN => v_pub = 0, note1 = 100, note2 = 0 || OUT => v_pub = 10, note1 = 70, note2 = 20");


    libff::enter_block("[START] Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    // Note: `make_unique` should be C++14 compliant, but here we use c++11, so we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree<FieldT, HashT>> test_merkle_tree = std::unique_ptr<merkle_tree<FieldT, HashT>>(
        new merkle_tree<FieldT, HashT>(
            ZETH_MERKLE_TREE_DEPTH
        )
    );
    libff::leave_block("[END] Instantiate merkle tree for the tests", true);


    // --- Test 1: Generate a valid proof for commitment inserted at address 1 -- //
    libff::enter_block("[BEGIN] Create JSInput", true);
    // Create the zeth note data for the commitment we will insert in the tree (commitment to spend in this test)
    FieldT r_trap = FieldT("6576838732374919021860119342200398901974877797242970520445052250557344565821");
    FieldT a_sk = FieldT("18834251028175908666459239027856614524890385928194459012149074634190864282942");
    FieldT a_pk = FieldT("5387907419355715653531038695566357046482139005118304712469340438697294642611");
    FieldT rho = FieldT("12946791413528024759839394340318236878559158148001437182189040772047964059643");
    FieldT nf = FieldT("11936680607858084380537967489495552519299143216151535029075478675240592155294");
    FieldT value = FieldT("100");
    FieldT cm = FieldT("7696443061196341087326334761452156208417519921123230974759309762690342959594");
    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm);
    FieldT updated_root_value = test_merkle_tree->get_root();
    std::vector<merkle_authentication_node> path = test_merkle_tree->get_path(address_commitment);

    // JS Inputs
    ZethNote<FieldT>note_input1(
        a_pk,
        FieldT("100"),
        rho,
        r_trap
    );

    ZethNote<FieldT>note_input2(
        a_pk,
        FieldT("0"),
        rho,
        r_trap
    );

    JSInput<FieldT> input1(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input1,
        a_sk,
        nf
    );

    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path check
    // Doesn't count in such case
    JSInput<FieldT> input2(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input2,
        a_sk,
        nf
    );

    std::array<JSInput<FieldT>, 2> inputs;
    inputs[0] = input1;
    inputs[1] = input2;
    libff::leave_block("[END] Create JSInput", true);



    libff::enter_block("[BEGIN] Create JSOutput/ZethNote", true);

    FieldT a_sk_out = FieldT("4047591473000155590199171927915978796573140621771266280705379796913645161555"); // mimic_hash([-1], sha3("Clearmatics"))
    FieldT a_pk_out = FieldT("5040863357084416281938805346896392895336796766724344426662331268783559604278");
    FieldT r_trap_out = FieldT("3121287842287349864642297846963883646477840388236905026425392648441319037621"); // mimic_hash([-2], sha3("Clearmatics"))
    FieldT rho_out = FieldT("10448869983030339500740742410361707713409326656173533049846269061232406471931"); // mimic_hash([-4], sha3("Clearmatics"))
    FieldT value_out_1 = FieldT("70");
    FieldT value_out_2 = FieldT("20");

    ZethNote<FieldT>note_output1(
        a_pk_out,
        value_out_1,
        rho_out,
        r_trap_out
    );

    ZethNote<FieldT>note_output2(
        a_pk_out,
        value_out_2,
        rho_out,
        r_trap_out
    );

    std::array<ZethNote<FieldT>, 2> outputs;
    outputs[0] = note_output1;
    outputs[1] = note_output2;
    libff::leave_block("[END] Create JSOutput/ZethNote", true);

    libff::enter_block("[BEGIN] Generate proof", true);
    // 100 = 70 + 20 + 10
    extended_proof<ppT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        FieldT("0"),
        FieldT("10"),
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
    CircuitWrapper<FieldT, HashT,2, 2> &prover,
    libzeth::keyPairT<ppT> keypair
) {
    // --- General setup for the tests --- //
    libff::print_header("Starting test: IN => v_pub = 10, note1 = 100, note2 = 0x0 || OUT => v_pub = 70, note1 = 20, note2 = 20");

    libff::enter_block("[START] Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    // Note: `make_unique` should be C++14 compliant, but here we use c++11, so we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree<FieldT, HashT>> test_merkle_tree = std::unique_ptr<merkle_tree<FieldT, HashT>>(
        new merkle_tree<FieldT, HashT>(
            ZETH_MERKLE_TREE_DEPTH
            )
    );
    libff::leave_block("[END] Instantiate merkle tree for the tests", true);



    // --- Test 1: Generate a valid proof for commitment inserted at address 1 -- //
    libff::enter_block("[BEGIN] Create JSInput", true);
    // Create the zeth note data for the commitment we will insert in the tree (commitment to spend in this test)
    FieldT r_trap = FieldT("6576838732374919021860119342200398901974877797242970520445052250557344565821");
    FieldT a_sk = FieldT("18834251028175908666459239027856614524890385928194459012149074634190864282942");
    FieldT a_pk = FieldT("5387907419355715653531038695566357046482139005118304712469340438697294642611");
    FieldT rho = FieldT("12946791413528024759839394340318236878559158148001437182189040772047964059643");
    FieldT nf = FieldT("11936680607858084380537967489495552519299143216151535029075478675240592155294");
    FieldT value = FieldT("100");
    FieldT cm = FieldT("7696443061196341087326334761452156208417519921123230974759309762690342959594");
    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm);
    FieldT updated_root_value = test_merkle_tree->get_root();
    std::vector<merkle_authentication_node> path = test_merkle_tree->get_path(address_commitment);

    // JS Inputs
    ZethNote<FieldT> note_input1(
        a_pk,
        value,
        rho,
        r_trap
    );

    ZethNote<FieldT> note_input2(
        a_pk,
        FieldT("0"),
        rho,
        r_trap
    );

    JSInput<FieldT> input1(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input1,
        a_sk,
        nf
    );

    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path check
    // Doesn't count in such case
    JSInput<FieldT> input2(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input2,
        a_sk,
        nf
    );

    std::array<JSInput<FieldT>, 2> inputs;
    inputs[0] = input1;
    inputs[1] = input2;
    libff::leave_block("[END] Create JSInput", true);



    libff::enter_block("[BEGIN] Create JSOutput/ZethNote", true);
    FieldT a_sk_out = FieldT("4047591473000155590199171927915978796573140621771266280705379796913645161555"); // mimic_hash([-1], sha3("Clearmatics"))
    FieldT a_pk_out = FieldT("5040863357084416281938805346896392895336796766724344426662331268783559604278");
    FieldT r_trap_out = FieldT("3121287842287349864642297846963883646477840388236905026425392648441319037621"); // mimic_hash([-2], sha3("Clearmatics"))
    FieldT rho_out = FieldT("10448869983030339500740742410361707713409326656173533049846269061232406471931"); // mimic_hash([-4], sha3("Clearmatics"))
    FieldT value_out_1 = FieldT("70");
    FieldT value_out_2 = FieldT("20");

    ZethNote<FieldT> note_output1(
        a_pk_out,
        value_out_1,
        rho_out,
        r_trap_out
    );
    ZethNote<FieldT> note_output2(
        a_pk_out,
        value_out_2,
        rho_out,
        r_trap_out
    );

    std::array<ZethNote<FieldT>, 2> outputs;
    outputs[0] = note_output1;
    outputs[1] = note_output2;
    libff::leave_block("[END] Create JSOutput/ZethNote", true);

    libff::enter_block("[BEGIN] Generate proof", true);
    //  100 + 0 + 10 = 70 + 20 + 20
    extended_proof<ppT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        FieldT("10"),
        FieldT("20"),
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







bool TestValidJS2In2Deposit(
    CircuitWrapper<FieldT, HashT, 2, 2> &prover,
    libzeth::keyPairT<ppT> keypair
) {
    // --- General setup for the tests --- //
    libff::print_header("Starting test: IN => v_pub = 100, note1 = 0, note2 = 0 || OUT => v_pub = 0, note1 = 80, note2 = 20");

    libff::enter_block("[START] Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    // Note: `make_unique` should be C++14 compliant, but here we use c++11, so we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree<FieldT, HashT>> test_merkle_tree = std::unique_ptr<merkle_tree<FieldT, HashT>>(
        new merkle_tree<FieldT, HashT>(
            ZETH_MERKLE_TREE_DEPTH
            )
    );
    libff::leave_block("[END] Instantiate merkle tree for the tests", true);



    // --- Test 1: Generate a valid proof for commitment inserted at address 1 -- //
    libff::enter_block("[BEGIN] Create JSInput", true);
    // Create the zeth note data for the commitment we will insert in the tree (commitment to spend in this test)
    FieldT r_trap = FieldT("6576838732374919021860119342200398901974877797242970520445052250557344565821");
    FieldT a_sk = FieldT("18834251028175908666459239027856614524890385928194459012149074634190864282942");
    FieldT a_pk = FieldT("5387907419355715653531038695566357046482139005118304712469340438697294642611");
    FieldT rho = FieldT("12946791413528024759839394340318236878559158148001437182189040772047964059643");
    FieldT nf = FieldT("11936680607858084380537967489495552519299143216151535029075478675240592155294");
    FieldT value = FieldT("0");
    FieldT cm = FieldT("3892611649031644221086393021396846773647511658795408370782400357314947699575");
    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm);
    FieldT updated_root_value = test_merkle_tree->get_root();
    std::vector<merkle_authentication_node> path = test_merkle_tree->get_path(address_commitment);

    // JS Inputs
    ZethNote<FieldT> note_input1(
        a_pk,
        value,
        rho,
        r_trap
    );

    ZethNote<FieldT> note_input2(
        a_pk,
        value,
        rho,
        r_trap
    );

    JSInput<FieldT> input1(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input1,
        a_sk,
        nf
    );

    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path check
    // Doesn't count in such case

    JSInput<FieldT> input2(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input2,
        a_sk,
        nf
    );

    std::array<JSInput<FieldT>, 2> inputs;
    inputs[0] = input1;
    inputs[1] = input2;
    libff::leave_block("[END] Create JSInput", true);



    libff::enter_block("[BEGIN] Create JSOutput/ZethNote", true);
    FieldT a_sk_out = FieldT("4047591473000155590199171927915978796573140621771266280705379796913645161555"); // mimic_hash([-1], sha3("Clearmatics"))
    FieldT a_pk_out = FieldT("5040863357084416281938805346896392895336796766724344426662331268783559604278");
    FieldT r_trap_out = FieldT("3121287842287349864642297846963883646477840388236905026425392648441319037621"); // mimic_hash([-2], sha3("Clearmatics"))
    FieldT rho_out = FieldT("10448869983030339500740742410361707713409326656173533049846269061232406471931"); // mimic_hash([-4], sha3("Clearmatics"))
    FieldT value_out_1 = FieldT("80");
    FieldT value_out_2 = FieldT("20");

    ZethNote<FieldT> note_output1(
        a_pk_out,
        value_out_1,
        rho_out,
        r_trap_out
    );

    ZethNote<FieldT> note_output2(
        a_pk_out,
        value_out_2,
        rho_out,
        r_trap_out
    );

    std::array<ZethNote<FieldT>, 2> outputs;
    outputs[0] = note_output1;
    outputs[1] = note_output2;
    libff::leave_block("[END] Create JSOutput/ZethNote", true);



    libff::enter_block("[BEGIN] Generate proof", true);
    // 0+ 0 +100 = 80 + 20 + 0
    extended_proof<ppT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        FieldT("100"),
        FieldT("00"),
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





bool TestInvalidJS2In2(
    CircuitWrapper<FieldT, HashT, 2, 2> &prover,
    libzeth::keyPairT<ppT> keypair
) {
    // --- General setup for the tests --- //
    libff::print_header("Starting test: IN => v_pub = 100, note1 = 0, note2 = 0 || OUT => v_pub = 0, note1 = 80, note2 = 70");

    libff::enter_block("[START] Instantiate merkle tree for the tests", true);
    // Create a merkle tree to run our tests
    // Note: `make_unique` should be C++14 compliant, but here we use c++11, so we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree<FieldT, HashT>> test_merkle_tree = std::unique_ptr<merkle_tree<FieldT, HashT>>(
        new merkle_tree<FieldT, HashT>(
            ZETH_MERKLE_TREE_DEPTH
            )
    );
    libff::leave_block("[END] Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1 -- //
    libff::enter_block("[BEGIN] Create JSInput", true);
    // Create the zeth note data for the commitment we will insert in the tree (commitment to spend in this test)
    FieldT r_trap = FieldT("6576838732374919021860119342200398901974877797242970520445052250557344565821");
    FieldT a_sk = FieldT("18834251028175908666459239027856614524890385928194459012149074634190864282942");
    FieldT a_pk = FieldT("5387907419355715653531038695566357046482139005118304712469340438697294642611");
    FieldT rho = FieldT("12946791413528024759839394340318236878559158148001437182189040772047964059643");
    FieldT nf = FieldT("11936680607858084380537967489495552519299143216151535029075478675240592155294");
    FieldT value = FieldT("0");
    FieldT cm = FieldT("3892611649031644221086393021396846773647511658795408370782400357314947699575");
    libff::bit_vector address_bits = {1, 0, 0, 0}; // 4 being the value of ZETH_MERKLE_TREE_DEPTH
    const size_t address_commitment = 1;

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm);
    FieldT updated_root_value = test_merkle_tree->get_root();
    std::vector<merkle_authentication_node> path = test_merkle_tree->get_path(address_commitment);

    // JS Inputs
    ZethNote<FieldT> note_input1(
        a_pk,
        value,
        rho,
        r_trap
    );

    ZethNote<FieldT> note_input2(
        a_pk,
        FieldT("0"),
        rho,
        r_trap
    );

    JSInput<FieldT> input1(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input1,
        a_sk,
        nf
    );

    // We keep the same path and address as the previous commitment
    // We don't care since this coin is zero-valued and the merkle auth path check
    // Doesn't count in such case
    JSInput<FieldT> input2(
        path,
        address_commitment,
        get_bitsAddr_from_vector(address_bits),
        note_input2,
        a_sk,
        nf
    );

    std::array<JSInput<FieldT>, 2> inputs;
    inputs[0] = input1;
    inputs[1] = input2;
    libff::leave_block("[END] Create JSInput", true);



    libff::enter_block("[BEGIN] Create JSOutput/ZethNote", true);
    FieldT a_sk_out = FieldT("4047591473000155590199171927915978796573140621771266280705379796913645161555"); // mimic_hash([-1], sha3("Clearmatics"))
    FieldT a_pk_out = FieldT("5040863357084416281938805346896392895336796766724344426662331268783559604278");
    FieldT r_trap_out = FieldT("3121287842287349864642297846963883646477840388236905026425392648441319037621"); // mimic_hash([-2], sha3("Clearmatics"))
    FieldT rho_out = FieldT("10448869983030339500740742410361707713409326656173533049846269061232406471931"); // mimic_hash([-4], sha3("Clearmatics"))
    FieldT value_out_1 = FieldT("80");
    FieldT value_out_2 = FieldT("70");

    ZethNote<FieldT> note_output1(
        a_pk_out,
        value_out_1,
        rho_out,
        r_trap_out
    );
    ZethNote<FieldT> note_output2(
        a_pk_out,
        value_out_2,
        rho_out,
        r_trap_out
    );
    std::array<ZethNote<FieldT>, 2> outputs;
    outputs[0] = note_output1;
    outputs[1] = note_output2;
    libff::leave_block("[END] Create JSOutput/ZethNote", true);



    libff::enter_block("[BEGIN] Generate proof", true);
    // 0 + 0 + 100 != 80 + 70 +0
    extended_proof<ppT> ext_proof = prover.prove(
        updated_root_value,
        inputs,
        outputs,
        FieldT("100"),
        FieldT("0"),
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




TEST(MainTests, ProofGenAndVerifJS2to2) {
    // Run the trusted setup once for all tests, and keep the keypair in memory for the duration of the tests
    CircuitWrapper<FieldT, HashT, 2, 2> proverJS2to2;
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
        std::cout << "[TestValidJS2In2Deposit] Expected (False), Obtained result: " << res << std::endl;
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
