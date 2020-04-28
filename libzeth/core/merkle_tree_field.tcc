// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/scipr-lab/libsnark/blob/master/libsnark/common/data_structures/merkle_tree.tcc

#ifndef __ZETH_CORE_MERKLE_TREE_FIELD_TCC__
#define __ZETH_CORE_MERKLE_TREE_FIELD_TCC__

#include "libzeth/core/merkle_tree_field.hpp"

#include <algorithm>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

namespace libzeth
{

template<typename FieldT, typename HashTreeT>
merkle_tree_field<FieldT, HashTreeT>::merkle_tree_field(const size_t depth)
    : depth(depth)
{
    assert(depth < sizeof(size_t) * 8);

    // Value of the leaves when initializing the merkle tree
    FieldT last = FieldT::zero();

    // Length of a merkle path = depth + 1
    // `hash_defaults` contains the default value of a merkle path
    // ie: The recursive hash of the zero valued leaves
    hash_defaults.reserve(depth + 1);
    hash_defaults.emplace_back(last);
    for (size_t i = 0; i < depth; ++i) {
        last = HashTreeT::get_hash(last, last);
        hash_defaults.push_back(last);
    }

    std::reverse(hash_defaults.begin(), hash_defaults.end());
}

template<typename FieldT, typename HashTreeT>
merkle_tree_field<FieldT, HashTreeT>::merkle_tree_field(
    const size_t depth, const std::vector<FieldT> &contents_as_vector)
    : merkle_tree_field<FieldT, HashTreeT>(depth)
{
    assert(libff::log2(contents_as_vector.size()) <= depth);
    for (size_t address = 0; address < contents_as_vector.size(); ++address) {
        // `1ul << depth` returns the total number of leaves in the merkle tree
        // of depth `depth`
        const size_t idx = address + (1ul << depth) - 1;
        values[idx] = contents_as_vector[address];
        hashes[idx] = contents_as_vector[address];
    }

    size_t idx_begin = (1ul << depth) - 1;
    size_t idx_end = contents_as_vector.size() + ((1ul << depth) - 1);

    for (int layer = depth; layer > 0; --layer) {
        for (size_t idx = idx_begin; idx < idx_end; idx += 2) {
            FieldT l = hashes[idx]; // this is sound, because idx_begin is
                                    // always a left child
            FieldT r =
                (idx + 1 < idx_end ? hashes[idx + 1] : hash_defaults[layer]);

            FieldT h = HashTreeT::get_hash(l, r);
            hashes[(idx - 1) / 2] = h;
        }

        idx_begin = (idx_begin - 1) / 2;
        idx_end = (idx_end - 1) / 2;
    }
}

template<typename FieldT, typename HashTreeT>
merkle_tree_field<FieldT, HashTreeT>::merkle_tree_field(
    const size_t depth, const std::map<size_t, FieldT> &contents)
    : merkle_tree_field<FieldT, HashTreeT>(depth)
{
    if (!contents.empty()) {
        assert(contents.rbegin()->first < 1ul << depth);

        for (auto it = contents.begin(); it != contents.end(); ++it) {
            const size_t address = it->first;
            const FieldT value = it->second;
            const size_t idx = address + (1ul << depth) - 1;

            values[address] = value;
            hashes[idx] = value;
        }

        auto last_it = hashes.end();

        for (int layer = depth; layer > 0; --layer) {
            auto next_last_it = hashes.begin();

            for (auto it = hashes.begin(); it != last_it; ++it) {
                const size_t idx = it->first;
                const FieldT hash = it->second;

                if (idx % 2 == 0) {
                    // this is the right child of its parent and by invariant we
                    // are missing the left child
                    hashes[(idx - 1) / 2] =
                        HashTreeT::get_hash(hash_defaults[layer], hash);
                } else {
                    if (std::next(it) == last_it ||
                        std::next(it)->first != idx + 1) {
                        // this is the left child of its parent and is missing
                        // its right child
                        hashes[(idx - 1) / 2] =
                            HashTreeT::get_hash(hash, hash_defaults[layer]);
                    } else {
                        // typical case: this is the left child of the parent
                        // and adjacent to it there is a right child
                        hashes[(idx - 1) / 2] =
                            HashTreeT::get_hash(hash, std::next(it)->second);
                        ++it;
                    }
                }
            }
            last_it = next_last_it;
        }
    }
}

template<typename FieldT, typename HashTreeT>
FieldT merkle_tree_field<FieldT, HashTreeT>::get_value(
    const size_t address) const
{
    assert(libff::log2(address) <= depth);

    auto it = values.find(address);
    FieldT result = (it == values.end() ? FieldT("0") : it->second);

    return result;
}

template<typename FieldT, typename HashTreeT>
void merkle_tree_field<FieldT, HashTreeT>::set_value(
    const size_t address, const FieldT &value)
{
    assert(libff::log2(address) <= depth);

    values[address] = value;

    // After adding the value, we update the nodes on its merkle path
    size_t idx = address + (1ul << depth) - 1;
    hashes[idx] =
        value; // The last element on the merkle path is the leaf value itself
    for (int layer = depth - 1; layer >= 0; --layer) {
        idx = (idx - 1) / 2;

        auto it = hashes.find(2 * idx + 1);
        FieldT l = (it == hashes.end() ? hash_defaults[layer + 1] : it->second);

        it = hashes.find(2 * idx + 2);
        FieldT r = (it == hashes.end() ? hash_defaults[layer + 1] : it->second);

        FieldT h = HashTreeT::get_hash(l, r);
        hashes[idx] = h;
    }
}

template<typename FieldT, typename HashTreeT>
FieldT merkle_tree_field<FieldT, HashTreeT>::get_root() const
{
    auto it = hashes.find(0);
    return (it == hashes.end() ? hash_defaults[0] : it->second);
}

template<typename FieldT, typename HashTreeT>
std::vector<FieldT> merkle_tree_field<FieldT, HashTreeT>::get_path(
    const size_t address) const
{

    // Create empty vector of size depth
    std::vector<FieldT> result(depth);

    // Check that the node given has address within tree range
    assert(libff::log2(address) <= depth);

    // Compute node address on tree
    size_t idx = address + (1ul << depth) - 1;

    // For each layer
    for (size_t layer = depth; layer > 0; --layer) {
        // Compute the sibling node address and retrieve it
        size_t sibling_idx = ((idx + 1) ^ 1) - 1;
        auto it = hashes.find(sibling_idx);

        // If last layer, retrieve sibling node value from vector values, else
        // from vector hashes
        if (layer == depth) {
            auto it2 = values.find(sibling_idx - ((1ul << depth) - 1));
            result[layer - 1] =
                (it2 == values.end() ? FieldT("0") : it2->second);
        } else {
            result[layer - 1] =
                (it == hashes.end() ? hash_defaults[layer] : it->second);
        }

        idx = (idx - 1) / 2;
    }

    std::reverse(result.begin(), result.end());
    return result;
}

template<typename FieldT, typename HashTreeT>
void merkle_tree_field<FieldT, HashTreeT>::dump() const
{
    // `1ul << depth`  returns the total number of leaves in the merkle tree of
    // depth `depth` Print the tree leaves (stored in the `values` map)
    std::cout << "* Merkle Tree Leaves" << std::endl;
    for (size_t i = 0; i < 1ul << depth; ++i) {
        auto it = values.find(i);
        const FieldT value = (it == values.end() ? FieldT("0") : it->second);
        std::cout << "[" << i << "] -> " << value << std::endl;
    }

    // We also dump the updated merkle path (after the insertion of the leaves)
    // and the value of the values in `hash_defaults` for a
    // debugging/information purpose To remove if this is useless.
    //
    // Print the inner nodes of the tree
    std::cout << "* Merkle Tree Inner Nodes (Debug)" << std::endl;
    for (auto it = hashes.cbegin(); it != hashes.cend(); ++it) {
        std::cout << "[" << it->first << "] -> " << it->second << std::endl;
    }
    std::cout << "* Merkle Tree `hash_defaults` (Debug)" << std::endl;
    for (size_t i = 0; i < hash_defaults.size(); i++) {
        std::cout << hash_defaults[i] << std::endl;
    }
}

} // namespace libzeth

#endif // __ZETH_CORE_MERKLE_TREE_FIELD_TCC__
