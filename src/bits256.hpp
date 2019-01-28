#ifndef __ZETH_BITS256_HPP__
#define __ZETH_BITS256_HPP__

#include <array>
#include <vector>

typedef std::array<bool, 256> bits256;
typedef std::array<bool, 64> bits64;
typedef std::array<bool, ZETH_MERKLE_TREE_DEPTH> bitsAddr;

#endif // __ZETH_BITS256_HPP__