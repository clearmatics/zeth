#include <libsnark/common/data_structures/merkle_tree.hpp>

#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>
#include <libsnark_helpers/libsnark_helpers.hpp>

#include "./computation/trusted_setup.hpp"
#include "./sha256/sha256_ethereum.cpp"

// We do this to avoid using namespace prefixes libsnark:: and libff::
// everytime we want to invoke something implemented in libsnark or libff
// respectively
using namespace libsnark;
using namespace libff;

/** 
 *  ------- Notes on Libsnark --------
 *  1) Gadgets are used in two modes: generating constraints via generate_r1cs_constraints (instance reduction) 
 *     and generating the witness via generate_r1cs_witness (witness reduction). 
 *     In the latter case, we don't need to generate constraints, we just assign values to variables and these 
 *     values hopefully satisfy the hypothetical constraints.
 *  2) https://en.cppreference.com/w/cpp/container/vector/emplace_back: Appends a new element to the end of the container
 *  3) http://www.cplusplus.com/reference/memory/shared_ptr/reset 
 **/

template<typename FieldT, typename HashT>
class Miximus {
    public:
        const size_t digest_len = HashT::get_digest_len();
        const size_t tree_depth = 4;

        /**
         *
         * See https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib2/examples/tutorial.cpp
         * for more details about the protoboard. It says that:
         * - The protoboard is the 'memory manager' which holds all constraints 
         * - (when creating the verifying circuit) and variable assignments (when creating the proof witness). 
         * - We specify the type as R1P, this can be augmented in the future to allow for BOOLEAN 
         * - or GF2_EXTENSION fields in the future.
         *
         * The line "protoboard<FieldT>" takes origin here: https://github.com/scipr-lab/libsnark/blob/92a80f74727091fdc40e6021dc42e9f6b67d5176/libsnark/gadgetlib1/protoboard.hpp#L30-L31
         * And makes use of the Cpp templates. Then, here we build a protoboard (we call the constructor)
         * by giving a type FieldT in the template.
         *
         */
        protoboard<FieldT> pb;

        // Def of multipacking_gadget here:
        // https://github.com/scipr-lab/libsnark/blob/92a80f74727091fdc40e6021dc42e9f6b67d5176/libsnark/gadgetlib1/gadgets/basic_gadgets.hpp#L47
        // This type of gadget contains a vector of packing gadgets as internal variable
        std::shared_ptr<multipacking_gadget<FieldT>> unpacker;
        std::shared_ptr<multipacking_gadget<FieldT>> unpacker1;

        std::shared_ptr<digest_variable<FieldT>> root_digest;
        std::shared_ptr<digest_variable<FieldT>> cm;
        std::shared_ptr<digest_variable<FieldT>> sk;
        std::shared_ptr<digest_variable<FieldT>> leaf_digest;

        std::shared_ptr<sha256_ethereum> cm_hash;

        std::shared_ptr<merkle_authentication_path_variable<FieldT, HashT>> path_variable;
        // See: libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp
        // The gadget checks the following: given a root R, address A, value V, and
        // authentication path P, check that P is a valid authentication path for the
        // value V as the A-th leaf in a Merkle tree with root R.
        std::shared_ptr<merkle_tree_check_read_gadget<FieldT, HashT>> check_membership;

        pb_variable_array<FieldT> address_bits_va; // Equivalent to positions var here: https://github.com/zcash/zcash/blob/master/src/zcash/circuit/merkle.tcc#L6
        std::shared_ptr <block_variable<FieldT>> input_variable;
        pb_variable<FieldT> ZERO;

        // I think there are 2 variable arrays because we want to prove 2 things
        // 1) Bob knows the sk
        // 2) The leaf associated with the sk is in the tree
        // TODO: Verify if I'm right or not
        pb_variable_array<FieldT> packed_inputs;
        pb_variable_array<FieldT> unpacked_inputs;
        
        pb_variable_array<FieldT> packed_inputs1;
        pb_variable_array<FieldT> unpacked_inputs1;

        // Constructor of the class "Miximus"
        Miximus() {
            // See: https://github.com/scipr-lab/libsnark/blob/92a80f74727091fdc40e6021dc42e9f6b67d5176/libsnark/gadgetlib1/pb_variable.hpp#L60
            packed_inputs.allocate(pb, 1 + 1, "packed");
            packed_inputs1.allocate(pb, 1 + 1, "packed");

            ZERO.allocate(pb, "ZERO");
            pb.val(ZERO) = 0;
            address_bits_va.allocate(pb, tree_depth, "address_bits");

            cm.reset(new digest_variable<FieldT>(pb, 256, "cm"));
            root_digest.reset(new digest_variable<FieldT>(pb, 256, "root_digest"));
            sk.reset(new digest_variable<FieldT>(pb, 256, "sk"));
            leaf_digest.reset(new digest_variable<FieldT>(pb, 256, "leaf_digest"));

            /**
             * multipacking_gadget(protoboard<FieldT> &pb,
             *        const pb_linear_combination_array<FieldT> &bits,
             *        const pb_linear_combination_array<FieldT> &packed_vars,
             *        const size_t chunk_size,
             *        const std::string &annotation_prefix="");
             **/
            // root_digest->bits.begin() and root_digest->bits.end() return iterators
            // See: http://www.cplusplus.com/reference/vector/vector/end/
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

            pb.set_input_sizes(18 + 1); // The size of the inputs is: 16 (leaves) + root + sk + cm (TODO: To verify)

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
            // merkle_authentication_path_variable<FieldT, HashT> path_variable(pb, tree_depth, "path_variable");

            // See definition of ONE (#define ONE pb_variable<FieldT>(0)) here:
            // https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/pb_variable.hpp#L74
            // Looking at https://github.com/zcash/zcash/blob/75546c697a964e77c14aa71b45403a0768c1f563/src/zcash/circuit/note.tcc#L161
            // And https://github.com/zcash/zcash/blob/75546c697a964e77c14aa71b45403a0768c1f563/src/zcash/circuit/note.tcc#L104-L108
            // And https://github.com/zcash/zcash/blob/75546c697a964e77c14aa71b45403a0768c1f563/src/zcash/circuit/note.tcc#L85-L91
            // The enforce value is used to know whether the value of a coin can be 0 or whether it should be strictly positive
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

            // Generate constraints
            // root_digest.generate_r1cs_constraints();
            unpacker->generate_r1cs_constraints(true); // enforce_bitness set to true
            unpacker1->generate_r1cs_constraints(false); // enforce_bitness set to false
            // See: https://github.com/zcash/zcash/issues/822
            // For more details about bitness/boolean enforcement

            generate_r1cs_equals_const_constraint<FieldT>(pb, ZERO, FieldT::zero(), "ZERO");
            cm_hash->generate_r1cs_constraints(true);
            path_variable->generate_r1cs_constraints();
            check_membership->generate_r1cs_constraints();
            leaf_digest->generate_r1cs_constraints();
        }
        
        void generate_trusted_setup() {
            // Generate keypair
            run_trusted_setup(pb);
        }

        // Generate the proof that is going to be verified by the Verifier solidity contract
        // Note: merkle_authentication_node is just a libff::bit_vector (which itself is just a std::vector<bool>)
        // See https://github.com/scipr-lab/libsnark/blob/92a80f74727091fdc40e6021dc42e9f6b67d5176/libsnark/common/data_structures/merkle_tree.hpp#L35
        bool prove(
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
            leaf_digest->generate_r1cs_witness(leaf); // TODO: See if I can delete this line (and thus delete the leaf arg of the function)
            root_digest->generate_r1cs_witness(node_root);

            bool is_valid_witness = pb.is_satisfied();
            assert(is_valid_witness);
            std::cout << "[DEBUG] Satisfiability result: " << is_valid_witness << "\n";

            // Build a proof using the witness built above and the proving key generated during the trusted setup
            generate_proof(pb);

            return is_valid_witness;
        }
};

int main () {
    // See: https://github.com/scipr-lab/libff/blob/master/libff/algebra/curves/alt_bn128/alt_bn128_init.cpp
    libff::alt_bn128_pp::init_public_params();
    typedef libff::Fr<libff::alt_bn128_pp> FieldT;

    // Instantiate the prover (TODO: Make it a singleton)
    Miximus<FieldT, sha256_ethereum> prover;

    // Run trusted setup
    prover.generate_trusted_setup();

    // Values given by the user
    libff::bit_vector node17 = { 0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 };
 libff::bit_vector node16 = { 1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,0 };
 libff::bit_vector node9 = { 1 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 };
 libff::bit_vector node5 = { 1 ,1 ,0 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,1 };
 libff::bit_vector node3 = { 1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,0 ,0 };
 libff::bit_vector node_root = { 0 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,1 };
 libff::bit_vector nullifier = { 1 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,0 };
 libff::bit_vector secret = { 1 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,1 };
    libff::bit_vector leaf = node16;
    
    libff::bit_vector address_bits;
    address_bits = {0,0,0,0};
    size_t address = 0;

    std::vector<merkle_authentication_node> merkle_path;
    merkle_path = {node3,node5,node9,node17};

    const size_t tree_depth = 4;

    bool valid_proof = prover.prove(merkle_path, secret, nullifier, leaf, node_root, address_bits, address, tree_depth);

    if (!valid_proof) {
        std::cout << "Invalid proof" << std::endl;
        return 1;
    }

    std::cout << "Proof generated successfully" << std::endl;
    return 0;
}
