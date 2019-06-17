// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.hpp
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.cpp

#ifndef __ZETH_MERKLE_PATH_AUTHENTICATOR_TCC__
#define __ZETH_MERKLE_PATH_AUTHENTICATOR_TCC__

namespace libzeth {

template<typename HashT, typename FieldT>
merkle_path_authenticator<HashT, FieldT>::merkle_path_authenticator(
        libsnark::protoboard<FieldT> &in_pb,
        const size_t in_depth,
        const libsnark::pb_variable_array<FieldT> in_address_bits,
        const libsnark::pb_variable<FieldT> in_leaf,
        const libsnark::pb_variable<FieldT> in_expected_root,
        const libsnark::pb_variable_array<FieldT> in_path,
        const std::string &in_annotation_prefix
    ) :
        merkle_path_compute<HashT,FieldT>(in_pb, in_depth, in_address_bits, in_leaf, in_path, in_annotation_prefix),
        m_expected_root(in_expected_root)
    { }

template<typename HashT, typename FieldT>
bool merkle_path_authenticator<HashT, FieldT>::is_valid()
{
    return this->pb.val(this->result()) == this->pb.val(m_expected_root);
}

template<typename HashT, typename FieldT>
void merkle_path_authenticator<HashT, FieldT>::generate_r1cs_constraints()
{
    merkle_path_compute<HashT, FieldT>::generate_r1cs_constraints();

    // Ensure root matches calculated path hash
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(this->result(), 1, m_expected_root),
        FMT(this->annotation_prefix, ".expected_root authenticator"));
}

} // libzeth

// __ZETH_MERKLE_PATH_AUTHENTICATOR_TCC__
#endif
