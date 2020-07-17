// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/core/field_element_utils.hpp"

#include <gtest/gtest.h>

using ppT = libzeth::ppT;
using Fr = libzeth::FieldT;
using Fqe = libff::Fqe<ppT>;
using Fqk = libff::Fqk<ppT>;

using bigint_t = libff::bigint<libzeth::FieldT::num_limbs>;

namespace
{

bigint_t dummy_bigint()
{
    Fr v = Fr::random_element();
    return v.as_bigint();
}

Fr dummy_field_element() { return Fr::random_element(); }

TEST(FieldElementUtilsTest, BigIntEncodeDecode)
{
    bigint_t bi = dummy_bigint();
    std::string bi_hex = libzeth::bigint_to_hex<Fr>(bi);
    bigint_t bi_decoded = libzeth::bigint_from_hex<Fr>(bi_hex);
    std::cout << "bi_hex: " << bi_hex << std::endl;
    std::cout << "bi_decoded_hex: " << libzeth::bigint_to_hex<Fr>(bi_decoded)
              << std::endl;

    ASSERT_EQ(2 * sizeof(bi.data), bi_hex.size());
    ASSERT_EQ(bi, bi_decoded);
}

TEST(FieldElementUtilsTest, FieldElementEncodeDecode)
{
    Fr fe = dummy_field_element();
    std::string fe_hex = libzeth::base_field_element_to_hex<Fr>(fe);
    std::cout << "fe_hex: " << fe_hex << std::endl;
    Fr fe_decoded = libzeth::field_element_from_hex<Fr>(fe_hex);
    ASSERT_EQ(fe, fe_decoded);
}

TEST(FieldElementUtilsTest, FieldElementEncode)
{
    Fr fe = dummy_field_element();
    std::string fe_hex = libzeth::base_field_element_to_hex<Fr>(fe);
    std::cout << "fe_hex: " << fe_hex << std::endl;

    Fqe el = Fqe::random_element();
    std::string el_hex = libzeth::ext_field_element_to_hex<Fqe>(el);
    std::cout << "el_hex: " << el_hex << std::endl;
}

TEST(FieldElementUtilsTest, FieldElementDecodeBadString)
{
    std::string invalid_hex = "xxx";
    ASSERT_THROW(
        libzeth::field_element_from_hex<Fr>(invalid_hex), std::exception);
};

} // namespace

int main(int argc, char **argv)
{
    ppT::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
