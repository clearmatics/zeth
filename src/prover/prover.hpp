#ifndef __ZETH_PROVER_HPP__
#define __ZETH_PROVER_HPP__

#include <libsnark/common/data_structures/merkle_tree.hpp>

#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>
#include <libsnark_helpers/libsnark_helpers.hpp>

#include <sha256/sha256_ethereum.hpp>
#include "computation.hpp"

using namespace libsnark;
using namespace libff;

// TODO: Refactor the prover to define a standard interface, and define a ProverT template
// to be able to us the CLI to generate proofs for different computations (ie: Different circuits)
template<typename FieldT, typename HashT>
class Miximus {
	public:
		const size_t tree_depth = 3; // We start with a small Merkle Tree of 2^3 leaves

		protoboard<FieldT> pb;

		// Multipacking gadgets for the 2 inputs
		std::shared_ptr<multipacking_gadget<FieldT>> multipacking_gadget_1;
		std::shared_ptr<multipacking_gadget<FieldT>> multipacking_gadget_2;

		// root_digest of the merkle tree, the commitment we want to "spend" is in
		std::shared_ptr<digest_variable<FieldT>> root_digest;

		// This is the nullifier
		// TODO: To be computed with a PRF from a random seed
		std::shared_ptr<digest_variable<FieldT>> nullifier;

		// This is the secret used, along the nullifier, to compute the commitment
		std::shared_ptr<digest_variable<FieldT>> commitment_secret;

		// commitment = sha256(nullifier||secret). This basically is the commitment
		// TODO: Complexify the commitment structure to add the value and so on
		std::shared_ptr<digest_variable<FieldT>> commitment;

		// hash gadget to generate the commitment from the nullifier and the commitment_secret
		// such that: commitment = sha256_ethereum(nullifier, commitment_secret)
		std::shared_ptr<sha256_ethereum<FieldT>> hash_gagdet;

		// merkle_authentication_path_variable is a list of length = merkle_tree_depth
		// whose elements are couples in the form: (left_digest, right_digest)
		std::shared_ptr<merkle_authentication_path_variable<FieldT, HashT>> path_variable;

		// The merkle_tree_check_read_gadget gadget checks the following:
		// given a root R, address A, value V, and authentication path P, check that P is
		// a valid authentication path for the value V as the A-th leaf in a Merkle tree with root R.
		std::shared_ptr<merkle_tree_check_read_gadget<FieldT, HashT>> check_membership;

		// Equivalent to positions var here:
		// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/merkle.tcc#L6
		pb_variable_array<FieldT> address_bits_va;

		// A block_variable is a type corresponding to the input of the hash_gagdet
		// Thus the different parts of the input are all put into a block_variable
		// in order to be hashed and constitute a commitment.
		std::shared_ptr <block_variable<FieldT>> inputs;

		pb_variable<FieldT> ZERO;

		// TODO:
		// `unpacked_inputs`, and `packed_inputs` should be `pb_linear_combination_array`
		// According to the constructor of the multipacking_gadget
		// Thus we should either:
		// 1. Convert them from `pb_variable_array` to `pb_linear_combination_array`
		// using the function pb_linear_combination_array(const pb_variable_array<FieldT> &arr) { for (auto &v : arr) this->emplace_back(pb_linear_combination<FieldT>(v)); }
		// from the `pb_linear_combination_array` class in `pb_variable.hpp`
		// OR
		// 2. Change the type of `unpacked_inputs`, and `packed_inputs`
		// to `pb_linear_combination_array` directly

		// First input in an "unpacked" form, ie: a sequence of bits
		pb_variable_array<FieldT> unpacked_root_digest;
		// First input in a "packed" form, ie: a sequence of field elements
		pb_variable_array<FieldT> packed_root_digest;

		// Second input in an "unpacked" form, ie: a sequence of bits
		pb_variable_array<FieldT> unpacked_nullifier;
		// Second input in a "packed" form, ie: a sequence of field elements
		pb_variable_array<FieldT> packed_nullifier;

		Miximus();
		void generate_trusted_setup();
		bool prove(
				std::vector<merkle_authentication_node> merkle_path,
				libff::bit_vector secret,
				libff::bit_vector nullifier,
				libff::bit_vector leaf,
				libff::bit_vector node_root,
				libff::bit_vector address_bits,
				size_t address,
				size_t tree_depth
				);
};

#include "prover.tcc"

#endif
