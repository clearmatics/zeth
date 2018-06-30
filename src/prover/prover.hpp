#ifndef __ZKSNARK_PROVER_HPP__
#define __ZKSNARK_PROVER_HPP__

#include <libsnark/common/data_structures/merkle_tree.hpp>

#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>
#include <libsnark_helpers/libsnark_helpers.hpp>

#include <sha256/sha256_ethereum.hpp>
#include "computation.hpp"

using namespace libsnark;
using namespace libff;

template<typename FieldT, typename HashT>
class Miximus {
    public:
        const size_t digest_len = HashT::get_digest_len();
        const size_t tree_depth = 4;

        protoboard<FieldT> pb;

        std::shared_ptr<multipacking_gadget<FieldT>> unpacker;
        std::shared_ptr<multipacking_gadget<FieldT>> unpacker1;

        std::shared_ptr<digest_variable<FieldT>> root_digest;
        std::shared_ptr<digest_variable<FieldT>> cm;
        std::shared_ptr<digest_variable<FieldT>> sk;
        std::shared_ptr<digest_variable<FieldT>> leaf_digest;

        std::shared_ptr<sha256_ethereum> cm_hash;

        std::shared_ptr<merkle_authentication_path_variable<FieldT, HashT>> path_variable;
        std::shared_ptr<merkle_tree_check_read_gadget<FieldT, HashT>> check_membership;

        pb_variable_array<FieldT> address_bits_va; // Equivalent to positions var here: https://github.com/zcash/zcash/blob/master/src/zcash/circuit/merkle.tcc#L6
        std::shared_ptr <block_variable<FieldT>> input_variable;
        pb_variable<FieldT> ZERO;

        pb_variable_array<FieldT> packed_inputs;
        pb_variable_array<FieldT> unpacked_inputs;
        
        pb_variable_array<FieldT> packed_inputs1;
        pb_variable_array<FieldT> unpacked_inputs1;

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
