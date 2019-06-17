// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.hpp
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.cpp

#ifndef __ZETH_MERKLE_PATH_SELECTOR_TCC__
#define __ZETH_MERKLE_PATH_SELECTOR_TCC__

namespace libzeth {

template<typename FieldT>
merkle_path_selector<FieldT>::merkle_path_selector(
    libsnark::protoboard<FieldT> &in_pb,
    const libsnark::pb_variable<FieldT>& in_input,
    const libsnark::pb_variable<FieldT>& in_pathvar,
    const libsnark::pb_variable<FieldT>& in_is_right,
    const std::string &in_annotation_prefix
) :
    libsnark::gadget<FieldT>(in_pb, in_annotation_prefix),
    m_input(in_input),
    m_pathvar(in_pathvar),
    m_is_right(in_is_right)
{
    m_left.allocate(in_pb, FMT(this->annotation_prefix, ".left"));

    m_right.allocate(in_pb, FMT(this->annotation_prefix, ".right"));
}

template<typename FieldT>
void merkle_path_selector<FieldT>::generate_r1cs_constraints()
{
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(m_is_right, m_pathvar - m_input, m_left - m_input),
        FMT(this->annotation_prefix, "is_right*pathvar + 1-is_right * input = left"));

    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(m_is_right, m_input - m_pathvar, m_right - m_pathvar),
        FMT(this->annotation_prefix, "is_right*input + 1-is_right * pathvar = right"));
}

template<typename FieldT>
void merkle_path_selector<FieldT>::generate_r1cs_witness()
{
    this->pb.val(m_left) = this->pb.val(m_input) +  this->pb.val(m_is_right) * ( this->pb.val(m_pathvar) -this->pb.val(m_input)  );

    this->pb.val(m_right) = this->pb.val(m_pathvar) +  this->pb.val(m_is_right) * ( this->pb.val(m_input) -this->pb.val(m_pathvar)  );
}

template<typename FieldT>
const libsnark::pb_variable<FieldT>& merkle_path_selector<FieldT>::left() {
    return m_left;
}

template<typename FieldT>
const libsnark::pb_variable<FieldT>& merkle_path_selector<FieldT>::right() {
    return m_right;
}


} // libzeth

// __ZETH_MERKLE_PATH_SELECTOR_TCC__
#endif
