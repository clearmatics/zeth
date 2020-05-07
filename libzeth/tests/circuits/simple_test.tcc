// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_TEST_SIMPLE_TEST_TCC__
#define __ZETH_TEST_SIMPLE_TEST_TCC__

#include "simple_test.hpp"

namespace libzeth
{
namespace test
{

template<typename FieldT> void simple_circuit(libsnark::protoboard<FieldT> &pb)
{
    using namespace libsnark;

    // Prover wants to show that, for a public 'y', he knows a secret
    // 'x' s.t.
    //
    //   x^3 + 4x^2 + 2x + 5 = y
    pb_variable<FieldT> x;
    pb_variable<FieldT> y;
    pb_variable<FieldT> g1;
    pb_variable<FieldT> g2;

    // Statement
    y.allocate(pb, "y");

    // Witness
    x.allocate(pb, "x");
    g1.allocate(pb, "g1");
    g2.allocate(pb, "g2");

    pb.set_input_sizes(1);

    // g1 == x * x
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, x, g1), "g1");

    // g2 == g1 * x
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(g1, x, g2), "g2");

    // y == (g2 + 4.g1 + 2x + 5) * 1
    pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(g2 + (4 * g1) + (2 * x) + 5, 1, y), "y");
}

} // namespace test
} // namespace libzeth

#endif // __ZETH_TEST_SIMPLE_TEST_TCC__
