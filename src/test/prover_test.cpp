#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure
#include <libsnark/common/data_structures/merkle_tree.hpp>

#include "libsnark_helpers/libsnark_helpers.hpp"

// Header to use the sha256_ethereum gadget
#include "sha256/sha256_ethereum.hpp"

using namespace libsnark;

typedef libff::Fr<libff::default_ec_pp> FieldT; // Should be alt_bn128 in the CMakeLists.txt
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

//template<typename ppT>
bool test_proof_verification()
{
    libff::print_header("=== Init parameters ===");
    libff::default_ec_pp::init_public_params();

    // Create a merkle tree to store our commitments
    // Remember that our commitment scheme relies on hashing the commitment value
    // (at least in this "dummy" implementation)
    // TODO: Change the commitment scheme in the future to optimize our circuits and
    // diminish the number of constraints
    // See: https://github.com/zcash/zcash/issues/2234#issuecomment-292419085
    // For more details on the security analysis of the switch from sha256 to Pedersen commitments
    //
    // As the merkle_tree constructor asks for a depth and, more importantly, about a "value_size"
    // we need to specify the size of the value leaves in our merkle tree. In the zerocash protocol
    // the values of the leaves in the merkle tree are commitments. Since we use SHA256 as hash function
    // to generate our commitments, the size of our commitments is 256 bits (same size of the digest_size)
    // as we also use sha256 to build our merkle tree out of the value leaves.
    const size_t test_tree_depth = 3;

    // Instantiate a merkle tree to run our tests
    std::shared_ptr<merkle_tree<HashT>> test_merkle_tree;
    test_merkle_tree.reset(new merkle_tree<HashT>(
                test_tree_depth,
                HashT::get_digest_len()
                )
            );

    // Create a commitment to add it to the merkle tree
    const libff::bit_vector nullifier = generate_digests(HashT::get_digest_len());

    std::ostream &stream = std::cout;
    std::cout << "=== Nullifier bit representation: " << std::endl;
    dump_bit_vector(stream, nullifier);

    const libff::bit_vector commitment_secret = generate_digests(HashT::get_digest_len());
    std::cout << "=== Commitment bit representation: " << std::endl;
    dump_bit_vector(stream, commitment_secret);

    libff::bit_vector inputs;
    inputs.insert(inputs.end(), nullifier.begin(), nullifier.end());
    inputs.insert(inputs.end(), commitment_secret.begin(), commitment_secret.end());

    std::cout << "=== Inputs bit representation: " << std::endl;
    dump_bit_vector(stream, inputs);

    //libff::bit_vector commitment = get_hash(&input);

    //std::cout << "DISPLAY CONTENT OF COMMITMENT";
    //libff::serialize_bit_vector(stream, &commitment)

    // get the root of the merkle tree before the addition of the leaf
    //auto root_value = test_merkle_tree->get_root();

    // Add a commitment in the address 0 (left most leaf)
    //test_merkle_tree->set_value(0, &commitment);

    // get the root of the merkle tree after the addition of the leaf
    //auto root_value_after = test_merkle_tree->get_root();

    return true;

   // libff::print_header("=== Generate a **valid** proof ===");
   // // 1. Generate a proof
   // //
   // // We declare an instance of the prover here to generate a proof to
   // // be verified as part of the test
   // Miximus<FieldT, sha256_ethereum> prover;

   // libff::print_header("=== Verify the proof ===");
   // // 2. Verify the proof
   // //
   // // Load the verification key
   // char* setup_dir;
   // setup_dir = std::getenv("ZETH_TRUSTED_SETUP_DIR");
   // boost::filesystem::path verif_key_raw("vk.raw");
   // boost::filesystem::path full_path_verif_key_raw = setup_dir / verif_key_raw;
   // auto vk = deserializeVerificationKeyFromFile(full_path_verif_key_raw);

   // libff::print_header("R1CS GG-ppzkSNARK Verifier");
   // const bool res = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(vk, primary_input, proof);
   // printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
   // printf("* The verification result is: %s\n", (res ? "PASS" : "FAIL"));

   // libff::print_header("=== Generate an **invalid** proof ===");

   // return res;
}

int main () {
    //test_proof_verification();
    libff::bit_vector vect = generate_digests(256);
    std::ofstream output_file("./testDebug.txt");
    std::ostream_iterator<bool> output_iterator(output_file, ",");
    std::copy(vect.begin(), vect.end(), output_iterator);

    bool res = test_proof_verification();
    assert(res == false);

    std::cout << " =========================== Res value: " << res << std::endl;

    return 0;
}
