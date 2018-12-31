#ifndef __ZETH_PROVER_TCC__
#define __ZETH_PROVER_TCC__

#include <libsnark_helpers/libsnark_helpers.hpp>
#include <libsnark/gadgetlib1/constraint_profiling.hpp>
#include "computation.hpp"

using namespace libsnark;
using namespace libff;

// Note:
// The commitment is computed from the nullifier, and the commitment_secret.
// Thus, the inputs to the proof are:
// - The nullifier
// - The commitment_secret, which is a 256-bit long string, that is added to the commitment computation
// That way you can only "spend" a commitment iff the you have the nullifier and the commitment_secret
// (basically the pre-image of the hash)
// A commitment is bound to the corresponding commitment by adding the nullifier
// as part of the hash pre-image

template<typename ppT, typename HashT>
Miximus<ppT, HashT>::Miximus() {
    // Note on packer gagdets
    // Using packer gadgets enables to add the fact that bits are packed
    // into field elements as part of the proof and make it verifiable by the verifier
    // That way the verifier can verify that bits were packed correctly, and that
    // the prover didn't try to fool him.
    // And more importantly, the verification key is shorter (than if everything was kept in the binary format)
    // and the verification time is shorter
    //
    // Here we allocate 1+1 (=2) variables on the protoboard
    // Because we pack 256 bits.
    // However, we work in a field, where elements are encoded on 253 bits
    // Thus, it is impossible to pack 256 bits into a single field element
    // We need to pack the first 253 bits into 1 field elements
    // and the last 3 bits into another field element
    //
    // The sha256 gadget works on the bit level.
    // That is why it has so many contraints everything needs to be decomposed to bits.
    // If we try to make each public input bits the verification key gets huge.
    // Because each bit has its own variable and we need to have a new element in the verification key for each variable.
    // This makes the gas of verifcation get huge.
    // So we use the packer to succinctly pass the variables from the contract to the snark.
    // We use 1+1 because the hash is 256 bits but the max variable availible in the snark is 253 bits.
    // So we need to have an extra variable to back these last 3 bits into.
    packed_root_digest.allocate(pb, 1 + 1, "packed_root_digest");
    packed_nullifier.allocate(pb, 1 + 1, "packed_nullifier");

    ZERO.allocate(pb, "ZERO");
    // See: https://github.com/scipr-lab/libsnark/blob/f7c87b88744ecfd008126d415494d9b34c4c1b20/libsnark/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/mp_pcd_circuits.tcc#L402
    pb.val(ZERO) = FieldT::zero();
    address_bits_va.allocate(pb, tree_depth, "address_bits");

    // Instantiate the nullifier, as a digest variables of size 256 bits
    // see:
    // digest_variable<FieldT>(protoboard<FieldT> &pb,
    //                        const size_t digest_size,
    //                        const std::string &annotation_prefix);
    // (first constructor in gadgetlib1/hashes/hash_io.hpp)
    const size_t digest_len = HashT::get_digest_len(); // Should be equal to 256 as we use sha256

    nullifier.reset(new digest_variable<FieldT>(pb, digest_len, "nullifier"));
    root_digest.reset(new digest_variable<FieldT>(pb, digest_len, "root_digest"));
    commitment_secret.reset(new digest_variable<FieldT>(pb, digest_len, "commitment_secret"));
    commitment.reset(new digest_variable<FieldT>(pb, digest_len, "commitment"));

    // While the packing_gadget adds constraint `result = \sum  bits[i] * 2^i`
    // A multipacking_gadget however, is able to pack bits into a set of field elements
    // Given a list of bits of length L, it can produce a list of results such that:
    // result_1 = \sum  bits[i] * 2^i (for i in [0, n])
    // result_2 = \sum  bits[i] * 2^i (for i in [n, 2n])
    // ...
    // result_m = \sum  bits[i] * 2^i (for i in [(m-1)*n, m*n])
    // Where m*n = L, and where n is the specified `chunk_size`.
    // Here, the `chunk_size` is the field capacity

    // Here `unpacked_inputs` is the bits sequence, and
    // `packed_inputs` is the correspondign list of field elements the bits have been packed into
    unpacked_root_digest.insert(unpacked_root_digest.end(), root_digest->bits.begin(), root_digest->bits.end());
    multipacking_gadget_1.reset(new multipacking_gadget<FieldT>(
                pb,
                unpacked_root_digest,
                packed_root_digest,
                FieldT::capacity(),
                "multipacking_gadget_1_root"
                )
            );

    unpacked_nullifier.insert(unpacked_nullifier.end(), nullifier->bits.begin(), nullifier->bits.end());
    multipacking_gadget_2.reset(new multipacking_gadget<FieldT>(
                pb,
                unpacked_nullifier,
                packed_nullifier,
                FieldT::capacity(),
                "multipacking_gadget_2_nullifier"
                )
            );

    // TODO: Set to the right number, and remember that the ONE variable in the R1CS
    // is hardcoded in the protoboard
    // Here we have only 4 input that, in reality, correspond only to 2 hashes, that are packed
    // in 4 fields elements (due to the field being smaller that the co-domain of SHA256)
    pb.set_input_sizes(4);

    // A block_variable is made of `parts` that are of type `pb_variable_array`
    // See, the constructors:
    // block_variable(protoboard<FieldT> &pb,
    //                const std::vector<pb_variable_array<FieldT> > &parts,
    //               const std::string &annotation_prefix);
    //
    // block_variable(protoboard<FieldT> &pb,
    //               const digest_variable<FieldT> &left,
    //               const digest_variable<FieldT> &right,
    //               const std::string &annotation_prefix);
    // Here we use the second constructor, where the nullifier == left part and
    // the commitment_secret == right part of the block
    inputs.reset(new block_variable<FieldT>(
                pb,
                *nullifier,
                *commitment_secret,
                "inputs"
                )
            );

    // hash_gagdet is the hash gadget to compute sha256(nullifier || commitment_secret)
    // Thus, hash_gagdet->generate_r1cs_witness()
    // assigns `commitment` to the value: `sha256(nullifier || commitment_secret)`
    //
    // Here the commitment scheme is sha256 as defined in ethereum (see the sha256 precompiled)
    // We also use this hasher to constitute our merkle tree
    hash_gagdet.reset(new sha256_ethereum<FieldT>(
                pb,
                SHA256_block_size,
                *inputs,
                *commitment,
                "hash_gagdet"
                )
            );

    // merkle_authentication_path_variable is a list of length = merkle_tree_depth
    // whose elements are couples in the form: (left_digest, right_digest)
    path_variable.reset(new merkle_authentication_path_variable<FieldT, HashT> (
                pb,
                tree_depth,
                "path_variable"
                )
            );

    // The merkle_tree_check_read_gadget gadget checks the following:
    // given a root R, address A, value V, and authentication path P, check that P is
    // a valid authentication path for the value V as the A-th leaf in a Merkle tree with root R.

    // Constructor:
    // merkle_tree_check_read_gadget(protoboard<FieldT> &pb,
    //       const size_t tree_depth,
    //       const pb_linear_combination_array<FieldT> &address_bits,
    //       const digest_variable<FieldT> &leaf_digest,
    //       const digest_variable<FieldT> &root_digest,
    //       const merkle_authentication_path_variable<FieldT, HashT> &path,
    //       const pb_linear_combination<FieldT> &read_successful,
    //       const std::string &annotation_prefix);
    // See: merkle_tree_check_read_gadget.hpp file
    // TODO: understand perfectly how the merkle_tree_check_read_gadget is implemented
    // and make sure I get all the information about how bit information is represented (LSB, MSB)
    check_membership.reset(new merkle_tree_check_read_gadget<FieldT, HashT>(
                pb,
                tree_depth,
                address_bits_va,
                *commitment,
                *root_digest,
                *path_variable,
                ONE,
                "check_membership"
                )
            );

    // We enforce_bitness in the mutlipacking gadgets to make sure they take bits
    // as input. This makes sure they actually pack bits in field elements.
    multipacking_gadget_1->generate_r1cs_constraints(true); // enforce_bitness set to true
    multipacking_gadget_2->generate_r1cs_constraints(true); // enforce_bitness set to true

    // generate_r1cs_equals_const_constraint<FieldT>(pb, ZERO, FieldT::zero(), "ZERO"); // useless, it just suffices to set ZERO to FieldT::zero() directly
    hash_gagdet->generate_r1cs_constraints(true); // ensure_output_bitness set to true
    path_variable->generate_r1cs_constraints();
    check_membership->generate_r1cs_constraints();
    commitment->generate_r1cs_constraints();

    std::cout << " // --------- Constraints profiling --------- // " << std::endl;
    PRINT_CONSTRAINT_PROFILING();
}

template<typename ppT, typename HashT>
libsnark::r1cs_ppzksnark_keypair<ppT> Miximus<ppT, HashT>::generate_trusted_setup() {
    // Generate a verification and proving key (trusted setup)
    libsnark::r1cs_ppzksnark_keypair<ppT> keypair = gen_trusted_setup<ppT>(pb);

    // Write the keys in a file
    write_setup(keypair); // Take the default path

    return keypair;

}

template<typename ppT, typename HashT>
extended_proof<ppT> Miximus<ppT, HashT>::prove(
        std::vector<merkle_authentication_node> merkle_path, // Secret input
        libff::bit_vector secret_bits, // Secret input
        libff::bit_vector nullifier_bits,
        libff::bit_vector commitment_bits, // The leaf we want to prove for in the merkle tree: Secret input
        libff::bit_vector root_bits,
        libff::bit_vector address_bits, // Secret input
        size_t address,
        size_t tree_depth, // TODO: Remove as this information is accessible directly inside the function (tree_depth is an attrbute of the Miximus class)
        libsnark::r1cs_ppzksnark_proving_key<ppT> proving_key // We pass all the inputs and the proving key to generate a proof
        ) {

    nullifier->generate_r1cs_witness(nullifier_bits);
    commitment_secret->generate_r1cs_witness(secret_bits);
    root_digest->generate_r1cs_witness(root_bits);
    hash_gagdet->generate_r1cs_witness();
    path_variable->generate_r1cs_witness(address, merkle_path);
    check_membership->generate_r1cs_witness();
    multipacking_gadget_1->generate_r1cs_witness_from_bits();
    multipacking_gadget_2->generate_r1cs_witness_from_bits();
    address_bits_va.fill_with_bits(pb, address_bits);
    commitment->generate_r1cs_witness(commitment_bits);

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "*** [DEBUG] Satisfiability result: " << is_valid_witness << " ***\n";

    // Build a proof using the witness built above and the proving key generated during the trusted setup
    extended_proof<ppT> ext_proof = gen_proof<ppT>(pb, proving_key);
    // Write the extended proof in a file
    ext_proof.write_extended_proof(); // Take the default path

    return ext_proof;
}

#endif
