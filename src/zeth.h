#ifndef __ZETH_CONSTANTS__
#define __ZETH_CONSTANTS__

#include <stddef.h>

static const size_t ZETH_NUM_JS_INPUTS = 2;
static const size_t ZETH_NUM_JS_OUTPUTS = 2;

static const size_t ZETH_MERKLE_TREE_DEPTH = 32;
static const size_t ZETH_MERKLE_TREE_DEPTH_TEST = 4;

static const size_t ZETH_V_SIZE = 8; // 64 bits for the value
static const size_t ZETH_RHO_SIZE = 32; // 256 bits for rho
static const size_t ZETH_A_SK_SIZE = 32; // 256 bits for rho
static const size_t ZETH_R_SIZE = 48; // 384 bits for r

// Size of a HashT digest in bits
// static const size_t ZETH_DIGEST_BIT_SIZE = 256;

// Size of a HashT digest in hex characters
static const size_t ZETH_DIGEST_HEX_SIZE = 64;

#endif // __ZETH_CONSTANTS__
