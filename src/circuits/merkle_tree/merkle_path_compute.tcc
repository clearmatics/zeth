// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.hpp
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/merkle_tree.cpp

#ifndef __ZETH_CIRCUITS_MERKLE_PATH_COMPUTE_TCC__
#define __ZETH_CIRCUITS_MERKLE_PATH_COMPUTE_TCC__

namespace libzeth
{

template<typename FieldT, typename HashTreeT>
merkle_path_compute<FieldT, HashTreeT>::merkle_path_compute(
    libsnark::protoboard<FieldT> &pb,
    const size_t depth,
    const libsnark::pb_variable_array<FieldT> &address_bits,
    const libsnark::pb_variable<FieldT> leaf,
    const libsnark::pb_variable_array<FieldT> &path,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , depth(depth)
    , address_bits(address_bits)
    , leaf(leaf)
    , path(path)
{
    // We first assert that we are not working with an empty tree
    // and that the leaf path is consistent with the tree size
    assert(depth > 0);
    assert(address_bits.size() == depth);

    // For each layer of the tree
    for (size_t i = 0; i < depth; i++) {
        // We first initialize the gadget to order the computed hash and the
        // authentication node to know which one is the first to be hashed and
        // which one is the second (as in mimc_hash(left, right)) We also append
        // the initialized gadget in the vector of selectors
        if (i == 0) {
            selectors.push_back(merkle_path_selector<FieldT>(
                pb,
                leaf,
                path[i],
                address_bits[i],
                FMT(this->annotation_prefix, " selector[%zu]", i)));
        } else {
            selectors.push_back(merkle_path_selector<FieldT>(
                pb,
                hashers[i - 1].result(),
                path[i],
                address_bits[i],
                FMT(this->annotation_prefix, " selector[%zu]", i)));
        }

        // We initialize the gadget to compute the next level hash input
        // with the level's authentication node and the previously computed hash
        HashTreeT t = HashTreeT(
            pb,
            {selectors[i].get_left()},
            selectors[i].get_right(),
            FMT(this->annotation_prefix, " hasher[%zu]", i));

        // We append the initialized hasher in the vector of hashers
        hashers.push_back(t);
    }
};

template<typename FieldT, typename HashTreeT>
void merkle_path_compute<FieldT, HashTreeT>::generate_r1cs_constraints()
{
    // For each level of the tree
    for (size_t i = 0; i < hashers.size(); i++) {
        // We constraint the selector and hash gadgets
        selectors[i].generate_r1cs_constraints();
        hashers[i].generate_r1cs_constraints();
    }
};

template<typename FieldT, typename HashTreeT>
void merkle_path_compute<FieldT, HashTreeT>::generate_r1cs_witness()
{
    // For each level of the tree
    for (size_t i = 0; i < hashers.size(); i++) {
        // We compute the left and right input of the hasher gadget
        // as well as the hash of left and right
        selectors[i].generate_r1cs_witness();
        hashers[i].generate_r1cs_witness();
    }
};

template<typename FieldT, typename HashTreeT>
const libsnark::pb_variable<FieldT> merkle_path_compute<FieldT, HashTreeT>::
    result()
{
    // We first check that we are not working with an empty tree
    assert(hashers.size() > 0);

    // We return the last hasher result, that is to say the computed root,
    // generated out of leaf, leaf address and merkle authentication path
    return hashers.back().result();
};

} // namespace libzeth

#endif // __ZETH_CIRCUITS_MERKLE_PATH_COMPUTE_TCC__