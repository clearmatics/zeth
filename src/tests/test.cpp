#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include "libsnark_helpers/libsnark_helpers.hpp"

using namespace libsnark;

// TODO: To finish
template<typename ppT>
bool test_proof_verification() {
    libff::print_header("=== Init parameters ===");
    libff::alt_bn128_pp::init_public_params();
    typedef libff::Fr<libff::alt_bn128_pp> FieldT;

    libff::print_header("=== Generate a **valid** proof ===");
    // 1. Generate a proof
    //
    // We declare an instance of the prover here to generate a proof to
    // be verified as part of the test
    Miximus<FieldT, sha256_ethereum> prover;

    libff::print_header("=== Verify the proof ===");
    // 2. Verify the proof
    //
    // Load the verification key
    char* setup_dir;
    setup_dir = std::getenv("ZETH_TRUSTED_SETUP_DIR");
    boost::filesystem::path verif_key_raw("vk.raw");
    boost::filesystem::path full_path_verif_key_raw = setup_dir / verif_key_raw;
    auto vk = deserializeVerificationKeyFromFile(full_path_verif_key_raw);

    libff::print_header("R1CS GG-ppzkSNARK Verifier");
    const bool res = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(vk, primary_input, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (res ? "PASS" : "FAIL"));

    libff::print_header("=== Generate an **invalid** proof ===");

    return res;
}

int main () {
    test_proof_verification();

    return 0;
}
