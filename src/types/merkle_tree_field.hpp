// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/scipr-lab/libsnark/blob/master/libsnark/common/data_structures/merkle_tree.hpp

#ifndef __ZETH_MERKLE_TREE_FIELD_HPP__
#define __ZETH_MERKLE_TREE_FIELD_HPP__

#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/utils.hpp>
#include <map>
#include <vector>

namespace libzeth
{

// Merkle Tree whose nodes are field elements
//
// A Merkle tree is maintained as two maps:
// - `values` = Map from addresses to values, and
// - `hashes` = Map from addresses to hashes.
//
// The second map maintains the intermediate hashes of a Merkle tree
// built atop the values currently stored in the tree (the
// implementation admits a very efficient support for sparse
// trees). Besides offering methods to load and store values, the
// class offers methods to retrieve the root of the Merkle tree and to
// obtain the authentication paths for (the value at) a given address.

// typedef FieldT merkle_authentication_node;
// typedef std::vector<merkle_authentication_node> merkle_authentication_path;

template<typename FieldT, typename HashTreeT> class merkle_tree_field
{

public:
    std::vector<FieldT> hash_defaults;
    std::map<size_t, FieldT> values;
    std::map<size_t, FieldT> hashes;
    size_t depth;

    merkle_tree_field(const size_t depth);
    merkle_tree_field(
        const size_t depth, const std::vector<FieldT> &contents_as_vector);
    merkle_tree_field(
        const size_t depth, const std::map<size_t, FieldT> &contents);

    FieldT get_value(const size_t address) const;
    void set_value(const size_t address, const FieldT &value);

    FieldT get_root() const;
    std::vector<FieldT> get_path(const size_t address) const;

    void dump() const;
};

} // namespace libzeth
#include "merkle_tree_field.tcc"

#endif // __ZETH_MERKLE_TREE_FIELD_HPP__
