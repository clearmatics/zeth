// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/util.hpp"

#include "gtest/gtest.h"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/public_params.hpp>
#include <libff/common/default_types/ec_pp.hpp>

// Access zeth configuration constants
#include "assert.h"
#include "libzeth/zeth.h"

// Instantiation of the templates for the tests
typedef libff::default_ec_pp ppT;

// Should be alt_bn128 in the CMakeLists.txt
typedef libff::Fr<ppT> FieldT;

namespace
{
TEST(TestHexConvertion, TestHexToFieldTrue)
{
    ppT::init_public_params();

    std::string sample =
        "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    FieldT expected_field_element =
        FieldT("144740111546645244279463731260859884816587480832050705049321980"
               "00989141204991");
    FieldT computed_field_element = libzeth::string_to_field<FieldT>(sample);

    bool res = false;
    res = (computed_field_element == expected_field_element);

    ASSERT_TRUE(res);
};

TEST(TestHexConvertion, TestHexToFieldFalse)
{
    ppT::init_public_params();

    std::string sample =
        "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1";
    FieldT expected_field_element =
        FieldT("144740111546645244279463731260859884816587480832050705049321980"
               "00989141204991");
    FieldT computed_field_element = libzeth::string_to_field<FieldT>(sample);

    bool res = false;
    res = (computed_field_element == expected_field_element);

    ASSERT_FALSE(res);
};

TEST(TestHexConvertion, TestHexToFieldSmallTrue)
{
    ppT::init_public_params();

    std::string sample = "1ffffffffffffffffffffffff";
    FieldT expected_field_element = FieldT("158456325028528675187087900671");
    FieldT computed_field_element = libzeth::string_to_field<FieldT>(sample);

    bool res = false;
    res = (computed_field_element == expected_field_element);

    ASSERT_TRUE(res);
};

TEST(TestHexConvertion, TestHexToFieldSmallFalse)
{
    ppT::init_public_params();

    std::string sample = "1fffffffffffffffffffffff1";
    FieldT expected_field_element = FieldT("158456325028528675187087900671");
    FieldT computed_field_element = libzeth::string_to_field<FieldT>(sample);

    bool res = false;
    res = (computed_field_element == expected_field_element);

    ASSERT_FALSE(res);
};

TEST(TestHexConvertion, TestHexToFieldMixedLetters)
{
    ppT::init_public_params();

    std::string sample = "1FfffFfffffffffffffffffff";
    FieldT expected_field_element = FieldT("158456325028528675187087900671");
    FieldT computed_field_element = libzeth::string_to_field<FieldT>(sample);

    bool res = false;
    res = (computed_field_element == expected_field_element);

    ASSERT_TRUE(res);
};

TEST(TestHexConvertion, TestHexToFieldBadString)
{
    ppT::init_public_params();

    std::string sample = "xxx";
    bool res = true;

    try {
        FieldT computed_field_element =
            libzeth::string_to_field<FieldT>(sample);
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
