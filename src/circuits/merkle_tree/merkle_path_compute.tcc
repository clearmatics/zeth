// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.hpp
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.cpp

#ifndef __ZETH_MERKLE_PATH_COMPUTE_TCC__
#define __ZETH_MERKLE_PATH_COMPUTE_TCC__

namespace libzeth {

template<typename HashT, typename FieldT>
merkle_path_compute<HashT, FieldT>::merkle_path_compute(
        libsnark::protoboard<FieldT> &in_pb,
        const size_t in_depth,
        const libsnark::pb_variable_array<FieldT>& in_address_bits,
        const libsnark::pb_variable<FieldT> in_leaf,
        const libsnark::pb_variable_array<FieldT>& in_path,
        const std::string &in_annotation_prefix
    ) :
        libsnark::gadget<FieldT>(in_pb, in_annotation_prefix),
        m_depth(in_depth),
        m_address_bits(in_address_bits),
        m_leaf(in_leaf),
        m_path(in_path)
    {
        assert( in_depth > 0 );
        assert( in_address_bits.size() == in_depth );

        for( size_t i = 0; i < m_depth; i++ )
        {
            if( i == 0 )
            {
                m_selectors.push_back(
                    merkle_path_selector<FieldT>(
                        in_pb, in_leaf, in_path[i], in_address_bits[i],
                        FMT(this->annotation_prefix, ".selector[%zu]", i)));
            }
            else {
                m_selectors.push_back(
                    merkle_path_selector<FieldT>(
                        in_pb, m_hashers[i-1].result(), in_path[i], in_address_bits[i],
                        FMT(this->annotation_prefix, ".selector[%zu]", i)));
            }

            auto t = HashT(
                    in_pb,
                    {m_selectors[i].left(), m_selectors[i].right()},
                    FMT(this->annotation_prefix, ".hasher[%zu]", i));
            m_hashers.push_back(t);
        }
    }

template<typename HashT, typename FieldT>
const libsnark::pb_variable<FieldT> merkle_path_compute<HashT, FieldT>::result()
{
    assert( m_hashers.size() > 0 );

    return m_hashers.back().result();
}

template<typename HashT, typename FieldT>
void merkle_path_compute<HashT, FieldT>::generate_r1cs_constraints()
{
    size_t i;
    for( i = 0; i < m_hashers.size(); i++ )
    {
        m_selectors[i].generate_r1cs_constraints();
        m_hashers[i].generate_r1cs_constraints();
    }
}

template<typename HashT, typename FieldT>
void merkle_path_compute<HashT, FieldT>::generate_r1cs_witness()
{
    size_t i;
    for( i = 0; i < m_hashers.size(); i++ )
    {
        m_selectors[i].generate_r1cs_witness();
        m_hashers[i].generate_r1cs_witness();
    }
}

} // libzeth

// __ZETH_MERKLE_PATH_COMPUTE_TCC__
#endif
