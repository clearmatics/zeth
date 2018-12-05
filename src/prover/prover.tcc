#ifndef __ZETH_PROVER_TCC__
#define __ZETH_PROVER_TCC__

#include <libsnark_helpers/libsnark_helpers.hpp>
#include "computation.hpp"

using namespace libsnark;
using namespace libff;

template<typename FieldT, typename HashT>
Miximus<FieldT, HashT>::Miximus() {
    packed_inputs.allocate(pb, 1 + 1, "packed");
    packed_inputs1.allocate(pb, 1 + 1, "packed");

    ZERO.allocate(pb, "ZERO");
    pb.val(ZERO) = 0;
    address_bits_va.allocate(pb, tree_depth, "address_bits");

    cm.reset(new digest_variable<FieldT>(pb, 256, "cm"));
    root_digest.reset(new digest_variable<FieldT>(pb, 256, "root_digest"));
    sk.reset(new digest_variable<FieldT>(pb, 256, "sk"));
    leaf_digest.reset(new digest_variable<FieldT>(pb, 256, "leaf_digest"));

    unpacked_inputs.insert(unpacked_inputs.end(), root_digest->bits.begin(), root_digest->bits.end());
    unpacker.reset(new multipacking_gadget<FieldT>(
            pb,
            unpacked_inputs,
            packed_inputs,
            FieldT::capacity(),
            "unpacker"
        )
    );

    unpacked_inputs1.insert(unpacked_inputs1.end(), cm->bits.begin(), cm->bits.end());
    unpacker1.reset(new multipacking_gadget<FieldT>(
            pb,
            unpacked_inputs1,
            packed_inputs1,
            FieldT::capacity(),
            "unpacker"
        )
    );

    pb.set_input_sizes(18 + 1);
    input_variable.reset(new block_variable<FieldT>(pb, *cm, *sk, "input_variable"));

    cm_hash.reset(new sha256_ethereum(
            pb,
            SHA256_block_size,
            *input_variable,
            *leaf_digest,
            "cm_hash"
        )
    );

    path_variable.reset(new  merkle_authentication_path_variable<FieldT, HashT> (
            pb,
            tree_depth,
            "path_variable"
        )
    );

    check_membership.reset(new merkle_tree_check_read_gadget<FieldT, HashT>(
            pb,
            tree_depth,
            address_bits_va,
            *leaf_digest,
            *root_digest,
            *path_variable,
            ONE,
            "check_membership"
        )
    );

    unpacker->generate_r1cs_constraints(true); // enforce_bitness set to true
    unpacker1->generate_r1cs_constraints(false); // enforce_bitness set to false

    generate_r1cs_equals_const_constraint<FieldT>(pb, ZERO, FieldT::zero(), "ZERO");
    cm_hash->generate_r1cs_constraints(true);
    path_variable->generate_r1cs_constraints();
    check_membership->generate_r1cs_constraints();
    leaf_digest->generate_r1cs_constraints();
}

template<typename FieldT, typename HashT>
void Miximus<FieldT, HashT>::generate_trusted_setup() {
    run_trusted_setup(pb);
}

template<typename FieldT, typename HashT>
bool Miximus<FieldT, HashT>::prove(
    std::vector<merkle_authentication_node> merkle_path,
    libff::bit_vector secret,
    libff::bit_vector nullifier,
    libff::bit_vector leaf,
    libff::bit_vector node_root,
    libff::bit_vector address_bits,
    size_t address,
    size_t tree_depth
) {
    cm->generate_r1cs_witness(nullifier);
    root_digest->generate_r1cs_witness(node_root);
    sk->generate_r1cs_witness(secret);
    cm_hash->generate_r1cs_witness();
    path_variable->generate_r1cs_witness(address, merkle_path);
    check_membership->generate_r1cs_witness();
    unpacker->generate_r1cs_witness_from_bits();
    unpacker1->generate_r1cs_witness_from_bits();

    address_bits_va.fill_with_bits(pb, address_bits);
    assert(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);

    // make sure that read checker didn't accidentally overwrite anything
    address_bits_va.fill_with_bits(pb, address_bits);
    unpacker->generate_r1cs_witness_from_bits();
    leaf_digest->generate_r1cs_witness(leaf);
    root_digest->generate_r1cs_witness(node_root);

    bool is_valid_witness = pb.is_satisfied();
    assert(is_valid_witness);
    std::cout << "[DEBUG] Satisfiability result: " << is_valid_witness << "\n";

    // Build a proof using the witness built above and the proving key generated during the trusted setup
    generate_proof(pb);

    return is_valid_witness;
}

#endif
