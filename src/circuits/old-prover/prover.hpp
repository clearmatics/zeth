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
template<typename ppT, typename HashT>
class Miximus {
    public:
        typedef libff::Fr<ppT> FieldT;

        // --  Attributes -- // --> defined in the zeth.h file
        // const size_t tree_depth; // Not needed anymore as it is defined in the zeth.h file

        // -- JoinSplit settings -- // --> Defined in the zeth.h file
        // Hardcoded to 2 to start with, and we'll see if we can increase this further later.
        // TODO: For now we keep the JoinSplit as simple as possible by enabling
        // to pour only 2 old coins into 2 newer coins. In the future, we want to replace most of the given
        // variables into arrays in order to enable to pour N coins into M other coins.
        //const size_t max_inputs = 2;
        //const size_t max_outputs = 2;

        // We define the max amount of a coin (testing purpose)
        const unsigned int max_amount = 1000;

        protoboard<libff::Fr<ppT> > pb;

        // Multipacking gadgets for the 2 inputs
        std::shared_ptr<multipacking_gadget<libff::Fr<ppT> > > multipacking_gadget_1;
        std::shared_ptr<multipacking_gadget<libff::Fr<ppT> > > multipacking_gadget_2;

        // root_digest of the merkle tree, the commitment we want to "spend" is in
        std::shared_ptr<digest_variable<libff::Fr<ppT> > > root_digest;

        //// ===== Variables used to compute the nullifier -- PRF
        std::shared_ptr<digest_variable<libff::Fr<ppT> > > rho; // Page 22, section 5.1 Zerocash extended paper (rho is set to be 256 bits)
        std::shared_ptr<digest_variable<libff::Fr<ppT> > > a_sk; // Page 22, section 5.1, paragraph "Instantiating the NP statement POUR" Zerocash extended paper (a_sk is set to be 256 bits)
        std::shared_ptr<digest_variable<libff::Fr<ppT> > > rho_front_padding; // Page 22, section 5.1, padding of '01' to pad rho in the generation of the serial nb
        std::shared_ptr<digest_variable<libff::Fr<ppT> > > nullifier_right_part; // Thsi is '01' || [rho]_254 (the 254 MSB of rho)

        //// ===== Variables used to generate the a_pk from a_sk -- PRF
        std::shared_ptr<digest_variable<libff::Fr<ppT> > > a_sk_back_padding; // Page 22, section 5.1, a_sk is padded by 256 0's to get a_pk
        std::shared_ptr<sha256_ethereum<libff::Fr<ppT> > > hash_gadget_a_pk; // Hash used to compute sha256(a_sk || 0^256)

        //// ===== Variables used to compute the inner commitment k (k = sha256(r || [sha256(a_pk || rho)]_128)), where r is a 384 bit string
        std::shared_ptr<digest_variable<libff::Fr<ppT> > > trap_r; // Here we are careful to set the length of this digest variable to 384 bits AND NOT digest_len !!!
        std::shared_ptr<digest_variable<libff::Fr<ppT> > > a_pk; // Page 22, section 5.1 Zerocash extended paper (a_pk is set to be 256 bits)
        std::shared_ptr<digest_variable<libff::Fr<ppT> > > inner_commitment_k;
        std::shared_ptr<digest_variable<libff::Fr<ppT> > > inner_commitment_k_left_part; // The left part of this commitment is the first 256 bits of trap_r
        std::shared_ptr<digest_variable<libff::Fr<ppT> > > inner_commitment_k_right_part; // The right part of this commitment is the last 128 bits of trap_r || the 128 most significant bits of [sha256(a_pk || rho)]_128
        std::shared_ptr<sha256_ethereum<libff::Fr<ppT> > > hash_gagdet_inner_commitment_k_inner; // Hash used to compute [sha256(a_pk || rho)]_128 in k
        std::shared_ptr<sha256_ethereum<libff::Fr<ppT> > > hash_gagdet_inner_commitment_k_outer; // Hash used to compute sha256(r || hash_inner)

        //// ===== Variables used to compute the outer commitment cm (that is appended in the merkle tree)
        std::shared_ptr<digest_variable<libff::Fr<ppT> > > value_v; // Page 22, section 5.1 Zerocash extended paper (value_v is set to be 64 bits)
        std::shared_ptr<digest_variable<libff::Fr<ppT> > > value_v_front_padding; // Page 22, section 5.1 Zerocash extended paper (the value_v is front padded with 192 0's)
        std::shared_ptr<digest_variable<libff::Fr<ppT> > > outer_commitment_right_part; // This is the digest made of 0^192 || value_v => 256-bit string
        std::shared_ptr<digest_variable<libff::Fr<ppT> > > outer_commitment_cm; // The left part of the outer commitment is the inner_commitment=_k

        // hash gadget to generate the commitment from the nullifier and the commitment_secret
        // such that: commitment = sha256_ethereum(nullifier, commitment_secret)
        std::shared_ptr<sha256_ethereum<libff::Fr<ppT> > > hash_gagdet_outer_commitment_cm; // Hash used to compute cm = sha256(k || 0^192 || value_v)

        // merkle_authentication_path_variable is a list of length = merkle_tree_depth
        // whose elements are couples in the form: (left_digest, right_digest)
        std::shared_ptr<merkle_authentication_path_variable<libff::Fr<ppT>, HashT> > path_variable;

        // The merkle_tree_check_read_gadget gadget checks the following:
        // given a root R, address A, value V, and authentication path P, check that P is
        // a valid authentication path for the value V as the A-th leaf in a Merkle tree with root R.
        std::shared_ptr<merkle_tree_check_read_gadget<libff::Fr<ppT>, HashT> > check_membership;

        // Equivalent to positions var here:
        // https://github.com/zcash/zcash/blob/master/src/zcash/circuit/merkle.tcc#L6
        pb_variable_array<libff::Fr<ppT> > address_bits_va; // TODO: See if this needs to be replaced by a pb_linear_combination_array (got an out of bound container error last time I tried... To investigate)

        // A block_variable is a type corresponding to the input of the hash_gagdet
        // Thus the different parts of the input are all put into a block_variable
        // in order to be hashed and constitute a commitment.
        std::shared_ptr <block_variable<libff::Fr<ppT> > > inputs;

        pb_variable<libff::Fr<ppT> > ZERO;

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
        pb_variable_array<libff::Fr<ppT> > unpacked_root_digest;
        // First input in a "packed" form, ie: a sequence of field elements
        pb_variable_array<libff::Fr<ppT> > packed_root_digest;

        // Second input in an "unpacked" form, ie: a sequence of bits
        pb_variable_array<libff::Fr<ppT> > unpacked_nullifier;
        // Second input in a "packed" form, ie: a sequence of field elements
        pb_variable_array<libff::Fr<ppT> > packed_nullifier;

        // -- Methods -- //
        Miximus(const size_t merkle_tree_depth);
        libsnark::r1cs_ppzksnark_keypair<ppT> generate_trusted_setup();
        extended_proof<ppT> prove(
                std::vector<merkle_authentication_node> merkle_path,
                libff::bit_vector secret_bits,
                libff::bit_vector nullifier_bits,
                libff::bit_vector commitment_bits,
                libff::bit_vector root_bits,
                libff::bit_vector address_bits,
                size_t address,
                libsnark::r1cs_ppzksnark_proving_key<ppT> proving_key
                );
};

#include "prover.tcc"

#endif
