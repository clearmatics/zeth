#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>

#include <libff/algebra/curves/public_params.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>

#include "util.hpp"

// Access zeth configuration constants
#include "zeth.h"

#include "assert.h"

using namespace libsnark;
using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT; // Should be alt_bn128 in the CMakeLists.txt

namespace {
TEST(TestHexConvertion, TestHexToFieldTrue) {
    ppT::init_public_params();

    std::string sample = "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    FieldT expected_field_element = FieldT("14474011154664524427946373126085988481658748083205070504932198000989141204991");

    FieldT computed_field_element = libzeth::string_to_field<FieldT>(sample);

    bool res = false;
    res = (computed_field_element == expected_field_element);

    ASSERT_TRUE(res);
};

TEST(TestHexConvertion, TestHexToFieldFalse) {
    ppT::init_public_params();

    std::string sample = "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1";
    FieldT expected_field_element = FieldT("14474011154664524427946373126085988481658748083205070504932198000989141204991");

    FieldT computed_field_element = libzeth::string_to_field<FieldT>(sample);

    bool res = false;
    res = (computed_field_element == expected_field_element);

    ASSERT_FALSE(res);
};

TEST(TestHexConvertion, TestHexToFieldSmallTrue) {
    ppT::init_public_params();

    std::string sample = "1ffffffffffffffffffffffff";
    FieldT expected_field_element = FieldT("158456325028528675187087900671");

    FieldT computed_field_element = libzeth::string_to_field<FieldT>(sample);

    bool res = false;
    res = (computed_field_element == expected_field_element);

    ASSERT_TRUE(res);
};

TEST(TestHexConvertion, TestHexToFieldSmallFalse) {
    ppT::init_public_params();

    std::string sample = "1fffffffffffffffffffffff1";
    FieldT expected_field_element = FieldT("158456325028528675187087900671");

    FieldT computed_field_element = libzeth::string_to_field<FieldT>(sample);

    bool res = false;
    res = (computed_field_element == expected_field_element);

    ASSERT_FALSE(res);
};

TEST(TestHexConvertion, TestHexToFieldMixedLetters) {
    ppT::init_public_params();

    std::string sample = "1FfffFfffffffffffffffffff";
    FieldT expected_field_element = FieldT("158456325028528675187087900671");

    FieldT computed_field_element = libzeth::string_to_field<FieldT>(sample);

    bool res = false;
    res = (computed_field_element == expected_field_element);

    ASSERT_TRUE(res);
};


TEST(TestHexConvertion, TestHexToFieldBadString) {
    ppT::init_public_params();

    std::string sample = "xxx";
    bool res = true;

    try
    {
      FieldT computed_field_element = libzeth::string_to_field<FieldT>(sample);
    }
    catch(const std::exception &exc)
    {
      res = false;
    }

    ASSERT_FALSE(res);
};

} // namespace

int main(int argc, char **argv) {
    ppT::init_public_params(); // /!\ WARNING: Do once for all tests. Do not forget to do this !!!!
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
