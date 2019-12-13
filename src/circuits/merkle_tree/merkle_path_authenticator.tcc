// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.hpp
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.cpp

#ifndef __ZETH_CIRCUITS_MERKLE_PATH_AUTHENTICATOR_TCC__
#define __ZETH_CIRCUITS_MERKLE_PATH_AUTHENTICATOR_TCC__

namespace libzeth
{

template<typename FieldT, typename HashTreeT>
merkle_path_authenticator<FieldT, HashTreeT>::merkle_path_authenticator(
    libsnark::protoboard<FieldT> &pb,
    const size_t depth,
    const libsnark::pb_variable_array<FieldT> address_bits,
    const libsnark::pb_variable<FieldT> leaf,
    const libsnark::pb_variable<FieldT> expected_root,
    const libsnark::pb_variable_array<FieldT> path,
    const libsnark::pb_variable<FieldT> bool_enforce,
    const std::string &annotation_prefix)
    : merkle_path_compute<FieldT, HashTreeT>(
          pb, depth, address_bits, leaf, path, annotation_prefix)
    , m_expected_root(expected_root)
    , value_enforce(bool_enforce)
{
}

template<typename FieldT, typename HashTreeT>
void merkle_path_authenticator<FieldT, HashTreeT>::generate_r1cs_constraints()
{
    // We ensure the computed root is constrained
    merkle_path_compute<FieldT, HashTreeT>::generate_r1cs_constraints();

    // We ensure, if bool_enforce is 1, that the expected root matches the
    // computed one
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(
            this->result() - this->m_expected_root, this->value_enforce, 0),
        FMT(this->annotation_prefix, " expected_root authenticator"));
}

template<typename FieldT, typename HashTreeT>
void merkle_path_authenticator<FieldT, HashTreeT>::generate_r1cs_witness()
{
    merkle_path_compute<FieldT, HashTreeT>::generate_r1cs_witness();
}

template<typename FieldT, typename HashTreeT>
bool merkle_path_authenticator<FieldT, HashTreeT>::is_valid()
{
    return this->pb.val(this->result()) == this->pb.val(m_expected_root);
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_MERKLE_PATH_AUTHENTICATOR_TCC__