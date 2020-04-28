// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/ff_utils.hpp"
#include "libzeth/core/utils.hpp"

#include <assert.h>
#include <gtest/gtest.h>

// Instantiation of the templates for the tests
using pp = libff::default_ec_pp;
using field = libff::Fr<pp>;

namespace
{

TEST(TestHexConvertion, TestHexToFieldTrue)
{
    field starting_field_element = field::random_element();
    std::string field_el_str =
        libzeth::libsnark_bigint_to_hexadecimal_str<field>(
            starting_field_element.as_bigint());

    // We read the string and convert it back to a field element
    field retrieved_field_element =
        libzeth::hexadecimal_str_to_field_element<field>(field_el_str);

    bool res = false;
    res = (starting_field_element == retrieved_field_element);
    ASSERT_TRUE(res);
};

TEST(TestHexConvertion, TestHexToFieldFalse)
{
    field starting_field_element = field::random_element();
    field modified_field_element = starting_field_element + field::one();
    std::string modified_field_el_str =
        libzeth::libsnark_bigint_to_hexadecimal_str<field>(
            modified_field_element.as_bigint());

    // We read the string and convert it back to a field element
    field retrieved_field_element =
        libzeth::hexadecimal_str_to_field_element<field>(modified_field_el_str);

    bool res = false;
    res = (starting_field_element == retrieved_field_element);
    ASSERT_FALSE(res);
};

TEST(TestHexConvertion, TestHexToFieldBadString)
{
    std::string sample = "xxx";
    bool res = true;

    try {
        field computed_field_element =
            libzeth::hexadecimal_str_to_field_element<field>(sample);
        libff::UNUSED(computed_field_element);
    } catch (const std::exception &exc) {
        res = false;
    }

    ASSERT_FALSE(res);
};

} // namespace

int main(int argc, char **argv)
{
    // /!\ WARNING: Do once for all tests. Do not
    // forget to do this !!!!
    pp::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
