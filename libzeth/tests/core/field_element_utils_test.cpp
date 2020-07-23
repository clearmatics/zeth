// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/field_element_utils.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>

namespace
{

template<typename FieldT> libff::bigint<FieldT::num_limbs> dummy_bigint()
{
    return FieldT::random_element().as_bigint();
}

template<typename FieldT> void do_bigint_encode_decode_hex_test()
{
    const libff::bigint<FieldT::num_limbs> bi = dummy_bigint<FieldT>();
    const std::string bi_hex = libzeth::bigint_to_hex<FieldT>(bi);
    const libff::bigint<FieldT::num_limbs> bi_decoded =
        libzeth::bigint_from_hex<FieldT>(bi_hex);
    std::cout << "bi_hex: " << bi_hex << std::endl;
    std::cout << "bi_decoded_hex: "
              << libzeth::bigint_to_hex<FieldT>(bi_decoded) << std::endl;

    ASSERT_EQ(2 * sizeof(bi.data), bi_hex.size());
    ASSERT_EQ(bi, bi_decoded);
}

template<typename ppT> void bigint_encode_decode_hex_test()
{
    do_bigint_encode_decode_hex_test<libff::Fr<ppT>>();
    do_bigint_encode_decode_hex_test<libff::Fq<ppT>>();
}

template<typename FieldT> void do_base_field_element_encode_decode_hex_test()
{
    const FieldT fe = FieldT::random_element();
    const std::string fe_hex = libzeth::base_field_element_to_hex<FieldT>(fe);
    std::cout << "fe_hex: " << fe_hex << std::endl;
    const FieldT fe_decoded =
        libzeth::base_field_element_from_hex<FieldT>(fe_hex);
    ASSERT_EQ(fe, fe_decoded);
}

template<typename ppT> void base_field_element_encode_decode_hex_test()
{
    do_base_field_element_encode_decode_hex_test<libff::Fr<ppT>>();
    do_base_field_element_encode_decode_hex_test<libff::Fq<ppT>>();
}

template<typename FieldT>
void do_base_field_element_encode_decode_hex_badstring_test()
{
    std::string invalid_hex = "xxx";
    ASSERT_THROW(
        libzeth::base_field_element_from_hex<FieldT>(invalid_hex),
        std::exception);
};

template<typename ppT>
void base_field_element_encode_decode_hex_badstring_test()
{
    do_base_field_element_encode_decode_hex_badstring_test<libff::Fr<ppT>>();
    do_base_field_element_encode_decode_hex_badstring_test<libff::Fq<ppT>>();
}

template<typename FieldT> void do_field_element_encode_decode_json_test()
{
    const FieldT fe = FieldT::random_element();
    const std::string fe_json = libzeth::field_element_to_json(fe);
    std::cout << "fe_json: '" << fe_json << "'" << std::endl;

    const FieldT fe_decoded = libzeth::field_element_from_json<FieldT>(fe_json);
    ASSERT_EQ(fe, fe_decoded);
}

template<typename ppT> void field_element_encode_decode_json_test()
{
    do_field_element_encode_decode_json_test<libff::Fr<ppT>>();
    do_field_element_encode_decode_json_test<libff::Fq<ppT>>();
    do_field_element_encode_decode_json_test<libff::Fqe<ppT>>();
    do_field_element_encode_decode_json_test<libff::Fqk<ppT>>();
}

template<typename FieldT>
void do_field_element_encode_decode_json_badstring_test()
{
    const FieldT fe = FieldT::random_element();
    std::string fe_json = libzeth::field_element_to_json(fe);
    // std::cout << "fe_json: '" << fe_json << "'" << std::endl;
    const size_t last_quote = fe_json.find_last_of('\"');
    ASSERT_NE(std::string::npos, last_quote);
    fe_json[last_quote] = ',';

    FieldT fe_decoded;
    ASSERT_THROW(
        fe_decoded = libzeth::field_element_from_json<FieldT>(fe_json),
        std::invalid_argument);
}

template<typename ppT> void field_element_encode_decode_json_badstring_test()
{
    do_field_element_encode_decode_json_badstring_test<libff::Fr<ppT>>();
    do_field_element_encode_decode_json_badstring_test<libff::Fq<ppT>>();
    do_field_element_encode_decode_json_badstring_test<libff::Fqe<ppT>>();
    do_field_element_encode_decode_json_badstring_test<libff::Fqk<ppT>>();
}

TEST(FieldElementUtilsTest, BigIntEncodeDecodeHex)
{
    bigint_encode_decode_hex_test<libff::alt_bn128_pp>();
    bigint_encode_decode_hex_test<libff::mnt4_pp>();
    bigint_encode_decode_hex_test<libff::mnt6_pp>();
}

TEST(FieldElementUtilsTest, BaseFieldElementEncodeDecodeHex)
{
    base_field_element_encode_decode_hex_test<libff::alt_bn128_pp>();
    base_field_element_encode_decode_hex_test<libff::mnt4_pp>();
    base_field_element_encode_decode_hex_test<libff::mnt6_pp>();
}

TEST(FieldElementUtilsTest, BaseFieldElementDecodeHexBadString)
{
    base_field_element_encode_decode_hex_badstring_test<libff::alt_bn128_pp>();
    base_field_element_encode_decode_hex_badstring_test<libff::mnt4_pp>();
    base_field_element_encode_decode_hex_badstring_test<libff::mnt6_pp>();
}

TEST(FieldElementUtilsTest, FieldElementEncodeDecodeJson)
{
    field_element_encode_decode_json_test<libff::alt_bn128_pp>();
    field_element_encode_decode_json_test<libff::mnt4_pp>();
    field_element_encode_decode_json_test<libff::mnt6_pp>();
}

TEST(FieldElementUtilsTest, FieldElementEncodeDecodeJsonBadString)
{
    field_element_encode_decode_json_badstring_test<libff::alt_bn128_pp>();
    field_element_encode_decode_json_badstring_test<libff::mnt4_pp>();
    field_element_encode_decode_json_badstring_test<libff::mnt6_pp>();
}

} // namespace

int main(int argc, char **argv)
{
    libff::alt_bn128_pp::init_public_params();
    libff::mnt4_pp::init_public_params();
    libff::mnt6_pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
