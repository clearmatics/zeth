// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_TEST_SIMPLE_TEST_HPP__
#define __ZETH_TEST_SIMPLE_TEST_HPP__

#include "libzeth/core/include_libsnark.hpp"

namespace libzeth
{
namespace tests
{

/// Generate a simple test circuit with 1 public input 'y' and auxiliary
/// inputs 'x', 'g1, and 'g2' for the expression:
///   x^3 + 4x^2 + 2x + 5 = y
/// where:
///   g1 = x * x
///   g2 = g1 * x
template<typename FieldT> void simple_circuit(libsnark::protoboard<FieldT> &pb);

/// Append a set of valid simple circuit inputs [ 'y', 'x', 'g1', 'g2' ] to
/// out_inputs. Note that out_primary can be the same as out_auxiliary (primary
/// input is appended first).
template<typename FieldT>
void simple_circuit_assignment(
    const FieldT &x,
    std::vector<FieldT> &out_primary,
    std::vector<FieldT> &out_auxiliary);

} // namespace tests
} // namespace libzeth

#include "simple_test.tcc"

#endif // __ZETH_TEST_SIMPLE_TEST_HPP__
