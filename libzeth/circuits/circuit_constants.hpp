// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_CIRCUIT_CONSTANTS_HPP__
#define __ZETH_CIRCUITS_CIRCUIT_CONSTANTS_HPP__

#include <stddef.h>

namespace libzeth
{

static const size_t ZETH_NUM_JS_INPUTS = 2;
static const size_t ZETH_NUM_JS_OUTPUTS = 2;

static const size_t ZETH_MERKLE_TREE_DEPTH = 32;

static const size_t ZETH_V_SIZE = 64;     // 64 bits for the value
static const size_t ZETH_RHO_SIZE = 256;  // 256 bits for rho
static const size_t ZETH_PHI_SIZE = 256;  // 256 bits for phi
static const size_t ZETH_HSIG_SIZE = 256; // 256 bits for h_sig
static const size_t ZETH_A_SK_SIZE = 256; // 256 bits for a_sk
static const size_t ZETH_A_PK_SIZE = 256; // 256 bits for a_pk
static const size_t ZETH_R_SIZE = 256;    // 256 bits for r

} // namespace libzeth

#endif // __ZETH_CIRCUITS_CIRCUIT_CONSTANTS_HPP__
