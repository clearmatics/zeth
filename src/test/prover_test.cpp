#include <memory>

#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure
#include <libsnark/common/data_structures/merkle_tree.hpp>

#include "libsnark_helpers/libsnark_helpers.hpp"

// Header to use the sha256_ethereum gadget
#include "sha256/sha256_ethereum.hpp"

// Header to use the Miximus (prover) gadget
#include "prover/prover.hpp"

using namespace libsnark;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT; // Should be alt_bn128 in the CMakeLists.txt
typedef sha256_ethereum<FieldT> HashT; // We use our hash function to do the tests

libff::bit_vector generate_digests(int digest_len)
{
    libff::bit_vector digest_bits;
    srand(time(0));
    for (int i = 0; i < digest_len; i++)
    {
        digest_bits.push_back(rand() % 2);
    }

    return digest_bits;
}

void dump_bit_vector(std::ostream &out, const libff::bit_vector &v)
{
    out << "{";
    for (size_t i = 0; i < v.size() - 1; ++i)
    {
        out << v[i] << ", ";
    }
    out << v[v.size() - 1] << "}\n";
}

template<typename ppT>
bool test_proof_verification(
        std::ostream &stream,
        Miximus<ppT, HashT> &prover,
        std::unique_ptr<merkle_tree<HashT>> &m_tree,
        libff::bit_vector nullifier,
        libff::bit_vector commitment_secret,
        size_t address_commitment,
        libff::bit_vector address_bits,
        const bool debug
    )
{
    libff::bit_vector inputs;
    inputs.insert(inputs.end(), nullifier.begin(), nullifier.end());
    inputs.insert(inputs.end(), commitment_secret.begin(), commitment_secret.end());

    libff::bit_vector commitment = HashT::get_hash(inputs);

    // Get the root of the merkle tree before the addition of the leaf
    auto initial_root_value = m_tree->get_root();

    // Add the commitment at the given address in the merkle tree (from left to right)
    m_tree->set_value(address_commitment, commitment);

    // Get the root of the merkle tree after the addition of the leaf
    auto updated_root_value = m_tree->get_root();

    if (debug)
    {
        std::cout << "=== Nullifier bit representation: " << std::endl;
        dump_bit_vector(stream, nullifier);
        std::cout << "=== [DEBUG] Commitment bit representation: ";
        dump_bit_vector(stream, commitment);
        std::cout << "=== [DEBUG] Inputs bit representation: " << std::endl;
        dump_bit_vector(stream, inputs);
        std::cout << "=== [DEBUG] Root before insertion bit representation: ";
        dump_bit_vector(stream, initial_root_value);
        std::cout << "=== [DEBUG] Root after insertion bit representation: ";
        dump_bit_vector(stream, updated_root_value);
    }

    // Get the merkle path to the commitment we inserted
    std::vector<merkle_authentication_node> path = m_tree->get_path(address_commitment);

    // Get the proving key - Need to run the trusted setup
    boost::filesystem::path setup_dir = getPathToSetupDir();
    boost::filesystem::path prov_key_raw("pk.raw");
    boost::filesystem::path path_prov_key_raw = setup_dir / prov_key_raw;
    libsnark::r1cs_ppzksnark_proving_key<ppT> pk = deserializeProvingKeyFromFile(path_prov_key_raw);

    // 1. Generate the proof
    libff::print_header("=== Generate the proof ===");
    extended_proof<ppT> ext_proof = prover.prove(
        path,
        commitment_secret,
        nullifier,
        commitment,
        updated_root_value,
        address_bits,
        address_commitment,
        pk
    );

    // 2. Verify the proof
    libff::print_header("=== Verify the proof ===");
    boost::filesystem::path verif_key_raw("vk.raw");
    boost::filesystem::path full_path_verif_key_raw = setup_dir / verif_key_raw;
    auto vk = deserializeVerificationKeyFromFile(full_path_verif_key_raw);

    libff::print_header("=== R1CS ppzkSNARK Verifier ===");
    return r1cs_ppzksnark_verifier_strong_IC<ppT>(vk, ext_proof.get_primary_input(), ext_proof.get_proof());
}

int main ()
{
    // --- General setup for the tests --- //
    libff::print_header("Starting prover tests");

    libff::enter_block("[START] General setup for the tests", true);
    libff::default_ec_pp::init_public_params();
    const size_t test_tree_depth = 3;

    // Create a prover for the tests
    Miximus<ppT, HashT> prover(test_tree_depth);
    // Run the trusted setup once for all tests
    prover.generate_trusted_setup();
    // Create a merkle tree to run our tests
    // Note: make_unique should be C++14 compliant, but here we use c++11, so we instantiate our unique_ptr manually
    std::unique_ptr<merkle_tree<HashT>> test_merkle_tree = std::unique_ptr<merkle_tree<HashT>>(
        new merkle_tree<HashT>(
            test_tree_depth,
            HashT::get_digest_len()
        )
    );
    std::ostream &stream = std::cout;
    libff::leave_block("[END] General setup for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at 0 address -- //
    libff::enter_block("[START] TEST1: Should be a valid proof", true);
    const libff::bit_vector nullifier = generate_digests(HashT::get_digest_len());
    const libff::bit_vector commitment_secret = generate_digests(HashT::get_digest_len());

    /*
     * Careful with bit ordering!
     * See comment in merkle_tree_check_read_gadget.tcc:
     * address_bits should be little endian (address_bits[0] -> LSB, and address_bits[depth-1] -> MSB)
     **/
    libff::bit_vector address_bits = {1, 0, 0}; // This binary string needs to be in little endian!
    const size_t address = 1;
    bool res = test_proof_verification<ppT>(
        stream,
        prover,
        test_merkle_tree,
        nullifier,
        commitment_secret,
        address,
        address_bits,
        true // Set the debug flag to get the result of every step
    );


    if (!res) {
        libff::enter_block("[END] TEST1: Should be a valid proof --> Result: FAIL", true);
        return 1;
    }
    libff::enter_block("[END] TEST1: Should be a valid proof --> Result: PASS", true);

    return 0;
}
