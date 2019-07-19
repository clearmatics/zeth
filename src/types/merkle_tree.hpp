#ifndef MERKLE_TREE_HPP_
#define MERKLE_TREE_HPP_

#include <map>
#include <vector>

#include <libff/common/utils.hpp>
#include <libff/common/default_types/ec_pp.hpp>


namespace libzeth {

/**
 * A Merkle tree is maintained as two maps:
 * - a map from addresses to values, and
 * - a map from addresses to hashes.
 *
 * The second map maintains the intermediate hashes of a Merkle tree
 * built atop the values currently stored in the tree (the
 * implementation admits a very efficient support for sparse
 * trees). Besides offering methods to load and store values, the
 * class offers methods to retrieve the root of the Merkle tree and to
 * obtain the authentication paths for (the value at) a given address.
 */
typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;
typedef FieldT merkle_authentication_node;
typedef std::vector<merkle_authentication_node> merkle_authentication_path;

template<typename FieldT, typename HashT>
class merkle_tree {

public:
    std::vector<FieldT> hash_defaults;
    std::map<size_t, FieldT> values;
    std::map<size_t, FieldT> hashes;
    size_t depth;

    merkle_tree(const size_t depth);
    merkle_tree(const size_t depth, const std::vector<FieldT> &contents_as_vector);
    merkle_tree(const size_t depth, const std::map<size_t, FieldT> &contents);

    FieldT get_value(const size_t address) const;
    void set_value(const size_t address, const FieldT &value);

    FieldT get_root() const;
    merkle_authentication_path get_path(const size_t address) const;

    void dump() const;
};

} // libsnark

#include <src/types/merkle_tree.tcc>

#endif // MERKLE_TREE_HPP_
