// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/core/group_element_utils.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>

using namespace libzeth;

namespace
{

template<typename ppT> void operation_test_data()
{
    // Generate data to be used to check the following operations
    //
    //   ecadd:
    //       [6] == [2] + [4]   (in G1)
    //   ecmul:
    //       [-8] == -2 * [4]   (in G1)
    //   ecpairing:
    //       e([6], [4]) * e([3],[8]) * e([4],[4]) * e([-8], [8]) == 1
    //
    // where [] represents exponentiation (all elements are in the
    // appropriate groups and fields, defined by context).

    const libff::Fr<ppT> fr_1 = libff::Fr<ppT>::one();
    const libff::Fr<ppT> fr_2 = fr_1 + fr_1;
    // const libff::Fr<ppT> fr_3 = fr_2 + fr_1;
    const libff::Fr<ppT> fr_minus_2 = -fr_2;

    const libff::G1<ppT> g1_1 = libff::G1<ppT>::one();
    const libff::G1<ppT> g1_2 = fr_2 * g1_1;
    const libff::G1<ppT> g1_3 = g1_1 + g1_2;
    const libff::G1<ppT> g1_4 = g1_2 + g1_2;
    const libff::G1<ppT> g1_6 = g1_2 + g1_4;
    const libff::G1<ppT> g1_8 = g1_4 + g1_4;

    const libff::G2<ppT> g2_1 = libff::G2<ppT>::one();
    const libff::G2<ppT> g2_2 = fr_2 * g2_1;
    const libff::G2<ppT> g2_4 = g2_2 + g2_2;
    const libff::G2<ppT> g2_8 = g2_4 + g2_4;

    std::cout << " Fr:";
    std::cout << "\n    r: "
              << bigint_to_hex<libff::Fr<ppT>>(libff::Fr<ppT>::mod);

    std::cout << "\n   -2: ";
    field_element_write_json(fr_minus_2, std::cout);

    std::cout << " Fq:";
    std::cout << "\n    q: "
              << bigint_to_hex<libff::Fq<ppT>>(libff::Fq<ppT>::mod);

    std::cout << "\n G1:";
    std::cout << "\n   1: ";
    point_affine_write_json(g1_1, std::cout);
    std::cout << "\n  -1: ";
    point_affine_write_json(-g1_1, std::cout);
    std::cout << "\n   2: ";
    point_affine_write_json(g1_2, std::cout);
    std::cout << "\n   3: ";
    point_affine_write_json(g1_3, std::cout);
    std::cout << "\n   4: ";
    point_affine_write_json(g1_4, std::cout);
    std::cout << "\n   6: ";
    point_affine_write_json(g1_6, std::cout);
    std::cout << "\n   8: ";
    point_affine_write_json(g1_8, std::cout);
    std::cout << "\n  -8: ";
    point_affine_write_json(-g1_8, std::cout);

    std::cout << "\n G2:";
    std::cout << "\n   1: ";
    point_affine_write_json(g2_1, std::cout);
    std::cout << "\n  -1: ";
    point_affine_write_json(-g2_1, std::cout);
    std::cout << "\n   4: ";
    point_affine_write_json(g2_4, std::cout);
    std::cout << "\n   8: ";
    point_affine_write_json(g2_8, std::cout);
    std::cout << "\n  -8: ";
    point_affine_write_json(-g2_8, std::cout);
    std::cout << "\n";

    // Check the statements above
    ASSERT_EQ(g1_6, g1_2 + g1_4);
    ASSERT_EQ(-g1_8, fr_minus_2 * g1_4);
    ASSERT_EQ(
        ppT::reduced_pairing(g1_6, g2_4) * ppT::reduced_pairing(g1_3, g2_8) *
            ppT::reduced_pairing(g1_4, g2_4) *
            ppT::reduced_pairing(-g1_8, g2_8),
        libff::GT<ppT>::one());
}

TEST(ECOperationDataTest, ALT_BN128)
{
    std::cout << "ALT_BN128:\n";
    operation_test_data<libff::alt_bn128_pp>();
}

TEST(ECOperationDataTest, BW6_761)
{
    std::cout << "BW6-761:\n";
    operation_test_data<libff::bw6_761_pp>();
}

TEST(ECOperationDataTest, BLS12_377)
{
    std::cout << "BLS12-377:\n";
    operation_test_data<libff::bls12_377_pp>();
}

} // namespace

int main(int argc, char **argv)
{
    libff::alt_bn128_pp::init_public_params();
    libff::bls12_377_pp::init_public_params();
    libff::bw6_761_pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
