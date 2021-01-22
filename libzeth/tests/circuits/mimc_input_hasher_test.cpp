// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/mimc/mimc_input_hasher.hpp"
#include "libzeth/circuits/mimc/mimc_mp.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>

namespace
{

using pp = libff::bls12_377_pp;
using Field = libff::Fr<pp>;
using comp_fn = libzeth::tree_hash_selector<Field>::tree_hash;
using input_hasher = libzeth::mimc_input_hasher<Field, comp_fn>;

TEST(MiMCInputHasherTest, SimpleInputValues)
{
    // Test data generated as follows:
    //   $ python
    //   >>> from zeth.core.mimc import MiMC31
    //   >>> from zeth.core.input_hasher import InputHasher
    //   >>> InputHasher(MiMC31()).hash([0,1,-1,2,-2])
    const std::vector<Field> simple_values{{
        Field::zero(),
        Field::one(),
        -Field::one(),
        Field("2"),
        -Field("2"),
    }};
    const Field expect_hash("47690627216444699952391427631776755329098419241452"
                            "8676152606007181154538262");

    libsnark::protoboard<Field> pb;

    // Public input: hash of multiple values
    libsnark::pb_variable<Field> hashed_inputs;
    hashed_inputs.allocate(pb, "hashed_inputs");
    pb.set_input_sizes(1);

    // Values to hash
    libsnark::pb_variable_array<Field> orig_inputs;
    orig_inputs.allocate(pb, simple_values.size(), "orig_inputs");

    // Input hasher
    input_hasher hasher(pb, orig_inputs, hashed_inputs, "hasher");

    // Constraints
    hasher.generate_r1cs_constraints();

    // Witness
    for (size_t i = 0; i < simple_values.size(); ++i) {
        pb.val(orig_inputs[i]) = simple_values[i];
    }
    hasher.generate_r1cs_witness();

    ASSERT_EQ(expect_hash, pb.val(hashed_inputs));
    ASSERT_EQ(expect_hash, input_hasher::compute_hash(simple_values));
    ASSERT_TRUE(pb.is_satisfied());
}

} // namespace

int main(int argc, char **argv)
{
    pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
