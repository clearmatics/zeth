#ifndef __ZETH_CIRCUIT_TYPES_HPP__
#define __ZETH_CIRCUIT_TYPES_HPP__

#include "circuit-wrapper.hpp"
#include "circuits/blake2s/blake2s_comp.hpp"
#include "include_libsnark.hpp"

// Types that must be common across all executable, defined once here.  Outside
// of tests, these should not be set anywhere else in the code.  Do not include
// this file in code that is generic (parameterized on ppT or FieldT).

// Use the pairing from build configuration
using ppT = libff::default_ec_pp;

// Field type for the pairing.
using FieldT = libff::Fr<ppT>;

// Hash used for the commitments and PRFs
using HashT = BLAKE2s_256_comp<FieldT>;

// Hash function to be used in the Merkle Tree
using HashTreeT = MiMC_mp_gadget<FieldT>;

#endif // __ZETH_CIRCUIT_TYPES_HPP__
