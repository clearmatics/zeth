// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/libsnark_helpers/debug_helpers.hpp"
#include "libzeth/util.hpp"
#include "libzeth/zeth.h"

#include "gtest/gtest.h"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/public_params.hpp>
#include <libff/common/default_types/ec_pp.hpp>

// Access zeth configuration constants
#include "assert.h"
#include "libzeth/zeth.h"

// Instantiation of the templates for the tests
typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;

namespace
{
TEST(TestHexConvertion, TestHexToFieldTrue)
{
    FieldT starting_field_element = FieldT::random_element();
    std::string field_el_str = libzeth::hex_from_libsnark_bigint<FieldT>(
        starting_field_element.as_bigint());

    // We read the string and convert it back to a field element
    FieldT retrieved_field_element =
        libzeth::hex_str_to_field_element<FieldT>(field_el_str);

    bool res = false;
    res = (starting_field_element == retrieved_field_element);
    ASSERT_TRUE(res);
};

TEST(TestHexConvertion, TestHexToFieldFalse)
{
    FieldT starting_field_element = FieldT::random_element();
    FieldT modified_field_element = starting_field_element + FieldT::one();
    std::string modified_field_el_str =
        libzeth::hex_from_libsnark_bigint<FieldT>(
            modified_field_element.as_bigint());

    // We read the string and convert it back to a field element
    FieldT retrieved_field_element =
        libzeth::hex_str_to_field_element<FieldT>(modified_field_el_str);

    bool res = false;
    res = (starting_field_element == retrieved_field_element);
    ASSERT_FALSE(res);
};

TEST(TestHexConvertion, TestHexToFieldBadString)
{
    std::string sample = "xxx";
    bool res = true;

    try {
        FieldT computed_field_element =
            libzeth::hex_str_to_field_element<FieldT>(sample);
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
    ppT::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
