// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/snarks/pghr13/pghr13_snark.hpp"
#include "libzeth/tests/snarks/common_snark_tests.tcc"

#include <gtest/gtest.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>

namespace
{

TEST(Pghr13SnarkTest, TestVerificationKeyReadWriteBytes)
{
    const bool test_alt_bn128 =
        libzeth::tests::verification_key_read_write_bytes_test<
            libff::alt_bn128_pp,
            libzeth::pghr13_snark<libff::alt_bn128_pp>>();
    ASSERT_TRUE(test_alt_bn128);

    const bool test_bls12_377 =
        libzeth::tests::verification_key_read_write_bytes_test<
            libff::bls12_377_pp,
            libzeth::pghr13_snark<libff::bls12_377_pp>>();
    ASSERT_TRUE(test_bls12_377);
}

TEST(Pghr13SnarkTest, TestProvingKeyReadWriteBytes)
{
    const bool test_alt_bn128 =
        libzeth::tests::proving_key_read_write_bytes_test<
            libff::alt_bn128_pp,
            libzeth::pghr13_snark<libff::alt_bn128_pp>>();
    ASSERT_TRUE(test_alt_bn128);
    const bool test_bls12_377 =
        libzeth::tests::proving_key_read_write_bytes_test<
            libff::bls12_377_pp,
            libzeth::pghr13_snark<libff::bls12_377_pp>>();
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
