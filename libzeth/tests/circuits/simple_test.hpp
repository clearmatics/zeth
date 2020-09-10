// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_TEST_SIMPLE_TEST_HPP__
#define __ZETH_TEST_SIMPLE_TEST_HPP__

#include "libzeth/core/include_libsnark.hpp"

namespace libzeth
{
namespace test
{

/// Generate a simple test circuit with 1 public input 'y' and auxiliary
///
/// input 'x', for the expression:
///
///   x^3 + 4x^2 + 2x + 5 = y
///
/// Internal auxiliary inputs are:
///
///   g1 = x * x
///   g2 = g1 * x
template<typename FieldT> void simple_circuit(libsnark::protoboard<FieldT> &pb);

} // namespace test
} // namespace libzeth

#include "simple_test.tcc"

#endif // __ZETH_TEST_SIMPLE_TEST_HPP__
