// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/field_element_utils.hpp"
#include "zeth_config.h"

#include <gtest/gtest.h>

using pp = libzeth::defaults::pp;
using FieldT = libzeth::defaults::FieldT;
using bigint_t = libff::bigint<FieldT::num_limbs>;

namespace
{

bigint_t dummy_bigint()
{
    FieldT v = FieldT::random_element();
    return v.as_bigint();
}

FieldT dummy_field_element() { return FieldT::random_element(); }

TEST(FieldElementUtilsTest, BigIntEncodeDecode)
{
    bigint_t bi = dummy_bigint();
    std::string bi_hex = libzeth::bigint_to_hex<FieldT>(bi);
    bigint_t bi_decoded = libzeth::bigint_from_hex<FieldT>(bi_hex);
    std::cout << "bi_hex: " << bi_hex << std::endl;
    std::cout << "bi_decoded_hex: "
              << libzeth::bigint_to_hex<FieldT>(bi_decoded) << std::endl;

    ASSERT_EQ(2 * sizeof(bi.data), bi_hex.size());
    ASSERT_EQ(bi, bi_decoded);
}

TEST(FieldElementUtilsTest, FieldElementEncodeDecode)
{
    FieldT fe = dummy_field_element();
    std::string fe_hex = libzeth::field_element_to_hex<FieldT>(fe);
    std::cout << "fe_hex: " << fe_hex << std::endl;
    FieldT fe_decoded = libzeth::field_element_from_hex<FieldT>(fe_hex);
    ASSERT_EQ(fe, fe_decoded);
}

TEST(FieldElementUtilsTest, FieldElementDecodeBadString)
{
    std::string invalid_hex = "xxx";
    ASSERT_THROW(
        libzeth::field_element_from_hex<FieldT>(invalid_hex), std::exception);
};

} // namespace

int main(int argc, char **argv)
{
    pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
