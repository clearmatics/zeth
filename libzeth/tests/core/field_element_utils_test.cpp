// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/field_element_utils.hpp"
#include "zeth_config.h"

#include <gtest/gtest.h>

using pp = libzeth::defaults::pp;
using Field = libzeth::defaults::Field;
using bigint_t = libff::bigint<Field::num_limbs>;

namespace
{

bigint_t dummy_bigint()
{
    Field v = Field::random_element();
    return v.as_bigint();
}

Field dummy_field_element() { return Field::random_element(); }

TEST(FieldElementUtilsTest, BigIntEncodeDecode)
{
    bigint_t bi = dummy_bigint();
    std::string bi_hex = libzeth::bigint_to_hex<Field>(bi);
    bigint_t bi_decoded = libzeth::bigint_from_hex<Field>(bi_hex);
    std::cout << "bi_hex: " << bi_hex << std::endl;
    std::cout << "bi_decoded_hex: " << libzeth::bigint_to_hex<Field>(bi_decoded)
              << std::endl;

    ASSERT_EQ(2 * sizeof(bi.data), bi_hex.size());
    ASSERT_EQ(bi, bi_decoded);
}

TEST(FieldElementUtilsTest, FieldElementEncodeDecode)
{
    Field fe = dummy_field_element();
    std::string fe_hex = libzeth::field_element_to_hex<Field>(fe);
    std::cout << "fe_hex: " << fe_hex << std::endl;
    Field fe_decoded = libzeth::field_element_from_hex<Field>(fe_hex);
    ASSERT_EQ(fe, fe_decoded);
}

TEST(FieldElementUtilsTest, FieldElementDecodeBadString)
{
    std::string invalid_hex = "xxx";
    ASSERT_THROW(
        libzeth::field_element_from_hex<Field>(invalid_hex), std::exception);
};

} // namespace

int main(int argc, char **argv)
{
    pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
