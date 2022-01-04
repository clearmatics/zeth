// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/serialization/r1cs_variable_assignment_serialization.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>

namespace
{

template<typename ppT> bool test_r1cs_variable_assignment_read_write_bytes()
{
    using FieldT = libff::Fr<ppT>;
    const size_t assignment_size = 37;
    const size_t primary_size = 3;

    libsnark::r1cs_variable_assignment<FieldT> assignment;
    assignment.reserve(assignment_size);
    for (size_t i = 0; i < assignment_size; ++i) {
        assignment.push_back(FieldT::random_element());
    }
    const libsnark::r1cs_primary_input<FieldT> primary(
        assignment.begin(), assignment.begin() + primary_size);
    const libsnark::r1cs_auxiliary_input<FieldT> auxiliary(
        assignment.begin() + primary_size, assignment.end());

    // Write as full assignment
    std::string buffer = ([&assignment]() {
        std::stringstream ss;
        libzeth::r1cs_variable_assignment_write_bytes(assignment, ss);
        return ss.str();
    })();

    // Read as full assignment
    libsnark::r1cs_variable_assignment<FieldT> assignment2;
    {
        std::stringstream ss(buffer);
        libzeth::r1cs_variable_assignment_read_bytes(assignment2, ss);
    }

    if (assignment != assignment2) {
        return false;
    }

    // Write as separate primary and auxiliary inputs
    buffer = ([&assignment]() {
        std::stringstream ss;
        libzeth::r1cs_variable_assignment_write_bytes(
            libsnark::r1cs_primary_input<FieldT>(
                assignment.begin(), assignment.begin() + primary_size),
            libsnark::r1cs_primary_input<FieldT>(
                assignment.begin() + primary_size, assignment.end()),
            ss);
        return ss.str();
    })();

    // Read back as full assignment
    {
        std::stringstream ss(buffer);
        libzeth::r1cs_variable_assignment_read_bytes(assignment2, ss);
    }

    if (assignment != assignment2) {
        return false;
    }

    // Read as separate primary in auxiliary
    libsnark::r1cs_primary_input<FieldT> primary2;
    libsnark::r1cs_auxiliary_input<FieldT> auxiliary2;
    {
        std::stringstream ss(buffer);
        libzeth::r1cs_variable_assignment_read_bytes(
            primary2, auxiliary2, primary_size, ss);
    }

    if (primary2 != primary || auxiliary2 != auxiliary) {
        return false;
    }

    // Passed
    return true;
}

TEST(R1CSVariableAssignementSerializationTest, AssignmentReadWriteBytes)
{
    const bool test_alt_bn128 =
        test_r1cs_variable_assignment_read_write_bytes<libff::alt_bn128_pp>();
    ASSERT_TRUE(test_alt_bn128);
    const bool test_bls12_377 =
        test_r1cs_variable_assignment_read_write_bytes<libff::bls12_377_pp>();
    ASSERT_TRUE(test_bls12_377);
}

} // namespace

int main(int argc, char **argv)
{
    libff::alt_bn128_pp::init_public_params();
    libff::bls12_377_pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
