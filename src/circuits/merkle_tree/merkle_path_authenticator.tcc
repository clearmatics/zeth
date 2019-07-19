// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.hpp
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.cpp

#ifndef __ZETH_MERKLE_PATH_AUTHENTICATOR_TCC__
#define __ZETH_MERKLE_PATH_AUTHENTICATOR_TCC__

namespace libzeth {

template<typename HashT, typename FieldT>
merkle_path_authenticator<HashT, FieldT>::merkle_path_authenticator(
        libsnark::protoboard<FieldT> &pb,
        const size_t depth,
        const libsnark::pb_variable_array<FieldT> address_bits,
        const libsnark::pb_variable<FieldT> leaf,
        const libsnark::pb_variable<FieldT> expected_root,
        const libsnark::pb_variable_array<FieldT> path,
        const libsnark::pb_variable<FieldT> bool_enforce,
        const std::string &annotation_prefix

    ) :
        merkle_path_compute<HashT,FieldT>(pb, depth, address_bits, leaf, path, annotation_prefix),
        m_expected_root(expected_root),
        value_enforce(bool_enforce)
    { 
        std::cout << "leaf" << this->pb.val(leaf) << std::endl;
        std::cout << "auth path" << std::endl;
        for (size_t i = 0; i < depth; i++)
        {
            std::cout << this->pb.val(path[i]) << std::endl;
        }
    }

template<typename HashT, typename FieldT>
void merkle_path_authenticator<HashT, FieldT>::generate_r1cs_constraints()
{
    // We ensure the computed root is constrained
    merkle_path_compute<HashT, FieldT>::generate_r1cs_constraints();

    // We ensure, if bool_enforce is 1, that the expected root matches the computed one
    this->pb.add_r1cs_constraint(
    libsnark::r1cs_constraint<FieldT>(this->result() - this->m_expected_root, this->value_enforce, 0),
    FMT(this->annotation_prefix, ".expected_root authenticator"));

}

template<typename HashT, typename FieldT>
void merkle_path_authenticator<HashT, FieldT>::generate_r1cs_witness()
{
    merkle_path_compute<HashT, FieldT>::generate_r1cs_witness();
}

template<typename HashT, typename FieldT>
bool merkle_path_authenticator<HashT, FieldT>::is_valid()
{
    return this->pb.val(this->result()) == this->pb.val(m_expected_root);
}

} // libzeth

// __ZETH_MERKLE_PATH_AUTHENTICATOR_TCC__
#endif
