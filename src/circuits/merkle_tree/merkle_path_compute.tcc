// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.hpp
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.cpp

#ifndef __ZETH_MERKLE_PATH_COMPUTE_TCC__
#define __ZETH_MERKLE_PATH_COMPUTE_TCC__

namespace libzeth {

template<typename HashT, typename FieldT>
merkle_path_compute<HashT, FieldT>::merkle_path_compute(
        libsnark::protoboard<FieldT> &pb,
        const size_t depth,
        const libsnark::pb_variable_array<FieldT>& address_bits,
        const libsnark::pb_variable<FieldT> leaf,
        const libsnark::pb_variable_array<FieldT>& path,
        const std::string &annotation_prefix
    ) :
        libsnark::gadget<FieldT>(pb, annotation_prefix),
        depth(depth),
        address_bits(address_bits),
        leaf(leaf),
        path(path)
    {
        assert( depth > 0 );
        assert( address_bits.size() == depth );

        libsnark::pb_variable<FieldT> iv;
        iv.allocate(pb, FMT(this->annotation_prefix, "_iv"));
        pb.val(iv) = FieldT("14220067918847996031108144435763672811050758065945364308986253046354060608451");

        for( size_t i = 0; i < depth; i++ )
        {
            if( i == 0 )
            {
                selectors.push_back(
                    merkle_path_selector<FieldT>(
                        pb, leaf, path[i], address_bits[i],
                        FMT(this->annotation_prefix, ".selector[%zu]", i)));
            }
            else {
                selectors.push_back(
                    merkle_path_selector<FieldT>(
                        pb, hashers[i-1].result(), path[i], address_bits[i],
                        FMT(this->annotation_prefix, ".selector[%zu]", i)));
            }

            HashT t = HashT(
                    pb,
                    {selectors[i].get_left(), selectors[i].get_right()},
                    iv,
                    FMT(this->annotation_prefix, ".hasher[%zu]", i));
            hashers.push_back(t);
        }
    }

template<typename HashT, typename FieldT>
const libsnark::pb_variable<FieldT> merkle_path_compute<HashT, FieldT>::result()
{
    assert( hashers.size() > 0 );

    return hashers.back().result();
}

template<typename HashT, typename FieldT>
void merkle_path_compute<HashT, FieldT>::generate_r1cs_constraints()
{
    size_t i;
    for( i = 0; i < hashers.size(); i++ )
    {
        selectors[i].generate_r1cs_constraints();
        hashers[i].generate_r1cs_constraints();
    }
}

template<typename HashT, typename FieldT>
void merkle_path_compute<HashT, FieldT>::generate_r1cs_witness()
{
    size_t i;
    for( i = 0; i < hashers.size(); i++ )
    {
        selectors[i].generate_r1cs_witness();
        hashers[i].generate_r1cs_witness();        
    }
}

} // libzeth

// __ZETH_MERKLE_PATH_COMPUTE_TCC__
#endif
