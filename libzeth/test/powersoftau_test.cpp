// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/utils.hpp"
#include "libzeth/snarks/groth16/mpc/evaluator_from_lagrange.hpp"
#include "libzeth/snarks/groth16/mpc/powersoftau_utils.hpp"

#include <boost/filesystem.hpp>
#include <fstream>
#include <gtest/gtest.h>

using ppT = libff::default_ec_pp;
using Fr = libff::Fr<ppT>;
using G1 = libff::G1<ppT>;
using G2 = libff::G2<ppT>;
using namespace libsnark;
using namespace libzeth;
namespace fs = boost::filesystem;

namespace
{

fs::path g_testdata_dir = fs::path("..") / "testdata";

static std::string hex_to_bin(const std::string &hex)
{
    return hexadecimal_str_to_binary_str(hex);
}

static std::string bin_to_hex(const std::string &hex)
{
    return binary_str_to_hexadecimal_str(hex);
}

G1 pot_hex_to_g1(const std::string &s)
{
    const std::string bin = hex_to_bin(s);
    std::istringstream ss_bytes(bin);
    G1 out;
    read_powersoftau_g1(ss_bytes, out);
    return out;
}

G2 pot_hex_to_g2(const std::string hex)
{
    const std::string bin = hex_to_bin(hex);
    std::istringstream ss_bytes(bin);
    G2 out;
    read_powersoftau_g2(ss_bytes, out);
    return out;
}

template<typename T> std::string to_hex(const T &v)
{
    std::ostringstream bufstream;
    bufstream << v;
    return bin_to_hex(bufstream.str());
}

template<typename T> using point_serializer_t = void(std::ostream &, const T &);

template<typename T> using point_deserializer_t = void(std::istream &, T &);

template<
    typename T,
    size_t expect_size,
    point_serializer_t<T> serialize,
    point_deserializer_t<T> deserialize>
void check_point_serialization(const T &v)
{
    const std::string serialized = [&v]() {
        std::ostringstream ss;
        serialize(ss, v);
        return ss.str();
    }();

    T deserialized;
    {
        std::istringstream ss(serialized);
        deserialize(ss, deserialized);
    };

    ASSERT_EQ(expect_size, serialized.size());
    ASSERT_EQ(v, deserialized);
}

TEST(PowersOfTauTests, SameRatioTest)
{
    // Correct and incorrect ratios

    Fr s = Fr::random_element();
    Fr r = Fr::random_element();
    Fr x = Fr::random_element();
    Fr xx = x + Fr::one();

    G1 s_g1 = s * G1::one();
    G1 s_x_g1 = x * s_g1;
    G2 r_g2 = r * G2::one();
    G2 r_x_g2 = x * r_g2;
    G1 s_xx_g1 = xx * s_g1;

    ASSERT_TRUE(same_ratio<ppT>(s_g1, s_x_g1, r_g2, r_x_g2));
    ASSERT_FALSE(same_ratio<ppT>(s_g1, s_xx_g1, r_g2, r_x_g2));
}

TEST(PowersOfTauTests, SameRatioBatchTest)
{
    // Create some powers and check $x^i$ vs $x^(i+1)$.
    const size_t num_powers = 8;
    const Fr x = Fr::random_element();
    const Fr alpha = Fr::random_element();
    const Fr xx = x + Fr::one();
    const G1 x_g1 = x * G1::one();
    const G2 x_g2 = x * G2::one();

    std::vector<G1> powers_g1(num_powers);
    std::vector<G1> powers_alpha_g1(num_powers);
    std::vector<G2> powers_g2(num_powers);
    std::vector<G2> powers_alpha_g2(num_powers);
    powers_g1[0] = G1::one();
    powers_alpha_g1[0] = alpha * G1::one();
    powers_g2[0] = G2::one();
    powers_alpha_g2[0] = alpha * G2::one();

    for (size_t i = 1; i < powers_g1.size(); ++i) {
        powers_g1[i] = x * powers_g1[i - 1];
        powers_alpha_g1[i] = x * powers_alpha_g1[i - 1];
        powers_g2[i] = x * powers_g2[i - 1];
        powers_alpha_g2[i] = x * powers_alpha_g2[i - 1];
    }

    std::vector<G1> invalid_powers_g1(powers_g1);
    invalid_powers_g1[4] = xx * invalid_powers_g1[3];
    std::vector<G2> invalid_powers_g2(powers_g2);
    invalid_powers_g2[4] = xx * invalid_powers_g2[3];

    // Check valid containers
    const bool valid_vectors_g1 = same_ratio_vectors<ppT>(
        powers_g1, powers_alpha_g1, G2::one(), powers_alpha_g2[0]);
    const bool valid_vectors_g2 = same_ratio_vectors<ppT>(
        G1::one(), powers_alpha_g1[0], powers_g2, powers_alpha_g2);
    const bool valid_consecutive_g1 =
        same_ratio_consecutive<ppT>(powers_g1, G2::one(), x_g2);
    const bool valid_consecutive_g2 =
        same_ratio_consecutive<ppT>(G1::one(), x_g1, powers_g2);

    ASSERT_TRUE(valid_vectors_g1);
    ASSERT_TRUE(valid_vectors_g2);
    ASSERT_TRUE(valid_consecutive_g1);
    ASSERT_TRUE(valid_consecutive_g2);

    // Invalid cases
    const bool invalid_vectors_g1 = same_ratio_vectors<ppT>(
        invalid_powers_g1, powers_alpha_g1, G2::one(), powers_alpha_g2[0]);
    const bool invalid_vectors_g2 = same_ratio_vectors<ppT>(
        G1::one(), powers_alpha_g1[0], invalid_powers_g2, powers_alpha_g2);
    const bool invalid_consecutive_g1 =
        same_ratio_consecutive<ppT>(invalid_powers_g1, G2::one(), x_g2);
    const bool invalid_consecutive_g2 =
        same_ratio_consecutive<ppT>(G1::one(), x_g1, invalid_powers_g2);

    ASSERT_FALSE(invalid_vectors_g1);
    ASSERT_FALSE(invalid_vectors_g2);
    ASSERT_FALSE(invalid_consecutive_g1);
    ASSERT_FALSE(invalid_consecutive_g2);
}

TEST(PowersOfTauTests, PowersOfTauIsWellFormed)
{
    const size_t n = 16;
    const srs_powersoftau<ppT> pot = dummy_powersoftau<ppT>(n);

    ASSERT_TRUE(powersoftau_is_well_formed(pot));

    // inconsistent sizes
    {
        libff::G1_vector<ppT> tau_powers_g1 = pot.tau_powers_g1;
        tau_powers_g1[2] = tau_powers_g1[2] + G1::one();
        const srs_powersoftau<ppT> tamper_sizes(
            std::move(tau_powers_g1),
            libff::G2_vector<ppT>(
                pot.tau_powers_g2.begin(), pot.tau_powers_g2.begin() + (n - 1)),
            libff::G1_vector<ppT>(
                pot.alpha_tau_powers_g1.begin(),
                pot.alpha_tau_powers_g1.begin() + (n - 1)),
            libff::G1_vector<ppT>(
                pot.beta_tau_powers_g1.begin(),
                pot.beta_tau_powers_g1.begin() + (n - 1)),
            pot.beta_g2);

        ASSERT_FALSE(powersoftau_is_well_formed(tamper_sizes));
    }

    // tamper with some individual entries
    {
        libff::G1_vector<ppT> tau_powers_g1 = pot.tau_powers_g1;
        tau_powers_g1[2] = tau_powers_g1[2] + G1::one();
        const srs_powersoftau<ppT> tamper_tau_g1(
            std::move(tau_powers_g1),
            libff::G2_vector<ppT>(pot.tau_powers_g2),
            libff::G1_vector<ppT>(pot.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(pot.beta_tau_powers_g1),
            pot.beta_g2);

        ASSERT_FALSE(powersoftau_is_well_formed(tamper_tau_g1));
    }

    {
        libff::G2_vector<ppT> tau_powers_g2 = pot.tau_powers_g2;
        tau_powers_g2[2] = tau_powers_g2[2] + G2::one();
        const srs_powersoftau<ppT> tamper_tau_g2(
            libff::G1_vector<ppT>(pot.tau_powers_g1),
            std::move(tau_powers_g2),
            libff::G1_vector<ppT>(pot.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(pot.beta_tau_powers_g1),
            pot.beta_g2);

        ASSERT_FALSE(powersoftau_is_well_formed(tamper_tau_g2));
    }

    {
        libff::G1_vector<ppT> alpha_tau_powers_g1 = pot.alpha_tau_powers_g1;
        alpha_tau_powers_g1[2] = alpha_tau_powers_g1[2] + G1::one();
        const srs_powersoftau<ppT> tamper_alpha_tau_g1(
            libff::G1_vector<ppT>(pot.tau_powers_g1),
            libff::G2_vector<ppT>(pot.tau_powers_g2),
            std::move(alpha_tau_powers_g1),
            libff::G1_vector<ppT>(pot.beta_tau_powers_g1),
            pot.beta_g2);

        ASSERT_FALSE(powersoftau_is_well_formed(tamper_alpha_tau_g1));
    }

    {
        libff::G1_vector<ppT> beta_tau_powers_g1 = pot.beta_tau_powers_g1;
        beta_tau_powers_g1[2] = beta_tau_powers_g1[2] + G1::one();
        const srs_powersoftau<ppT> tamper_beta_tau_g1(
            libff::G1_vector<ppT>(pot.tau_powers_g1),
            libff::G2_vector<ppT>(pot.tau_powers_g2),
            libff::G1_vector<ppT>(pot.alpha_tau_powers_g1),
            std::move(beta_tau_powers_g1),
            pot.beta_g2);

        ASSERT_FALSE(powersoftau_is_well_formed(tamper_beta_tau_g1));
    }

    {
        const srs_powersoftau<ppT> tamper_beta_g2(
            libff::G1_vector<ppT>(pot.tau_powers_g1),
            libff::G2_vector<ppT>(pot.tau_powers_g2),
            libff::G1_vector<ppT>(pot.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(pot.beta_tau_powers_g1),
            pot.beta_g2 + G2::one());

        ASSERT_FALSE(powersoftau_is_well_formed(tamper_beta_g2));
    }
}

TEST(UtilTest, ReadWritePowersOfTauFr)
{
    const Fr fr_1 = Fr::one();
    const Fr fr_2 = fr_1 + fr_1;
    const Fr fr_4 = fr_2 + fr_2;
    const Fr fr_7 = fr_4 + fr_2 + fr_1;
    const Fr fr_7_inv = fr_7.inverse();

    // 7.inv() (in F) binary encoded by powers-of-tau
    static const std::string s_f_7_inv =
        "06e9c21069503b73ac9dc0d0edede80d4ee2d80a5a8834a709b290cbfdb6db6e";

    Fr fr_7_inv_read;
    {
        std::istringstream ss_bytes(hex_to_bin(s_f_7_inv));
        read_powersoftau_fr(ss_bytes, fr_7_inv_read);
    }

    std::string fr_7_inv_write;
    {
        std::ostringstream out;
        write_powersoftau_fr(out, fr_7_inv);
        fr_7_inv_write = bin_to_hex(out.str());
    }

    ASSERT_EQ(fr_7_inv, fr_7_inv_read);
    ASSERT_EQ(s_f_7_inv, fr_7_inv_write);
}

TEST(UtilTest, ReadWritePowersOfTauG1)
{
    const Fr fr_1 = Fr::one();
    const Fr fr_2 = fr_1 + fr_1;
    const Fr fr_4 = fr_2 + fr_2;
    const Fr fr_7 = fr_4 + fr_2 + fr_1;
    const Fr expect_fr_7_inv = fr_7.inverse();
    const G1 expect_g1_7_inv = expect_fr_7_inv * G1::one();

    const std::string s_g1_0 = "00";
    const std::string s_g1_1 =
        "04"
        "0000000000000000000000000000000000000000000000000000000000000001"
        "0000000000000000000000000000000000000000000000000000000000000002";
    const std::string s_g1_7_inv =
        "04"
        "00e0ee2def593392a7a94e9bbbac1d4b104dbe5b6ec573eb04105efeaed342ca"
        "0fa5508a1ea35c78b4b7fc8eefa700c2ba6dba17b6747b89f7ddfdd7e38a39d8";

    std::string g1_7_inv_write;
    {
        std::ostringstream out;
        write_powersoftau_g1(out, expect_g1_7_inv);
        g1_7_inv_write = bin_to_hex(out.str());
    }

    ASSERT_EQ(G1::zero(), pot_hex_to_g1(s_g1_0));
    ASSERT_EQ(G1::one(), pot_hex_to_g1(s_g1_1));
    ASSERT_EQ(expect_g1_7_inv, pot_hex_to_g1(s_g1_7_inv));
    ASSERT_EQ(s_g1_7_inv, g1_7_inv_write);
}

TEST(UtilTest, ReadWritePowersOfTauFq2)
{
    const std::string fq2_x_string =
        "04d4bf3239f77cee7b47c7245e9281b3e9c1182d6381a87bbf81f9f2a6254b73"
        "1df569cda95e060bee91ba69b3f2d103658a7aea6b10e5bdc761e5715e7ee4bb";

    const std::string fq2_y_string =
        "01b4c328f0cbdb4aada63b3d09100d792376b94d07a6004e46054eeec849e8de"
        "9835158a11d28483dd8db236ea49f3630edc9e41944e494c5aacfc36af3b66e7";

    const libff::alt_bn128_Fq2 g2_one_x = G2::one().X;
    const libff::alt_bn128_Fq2 g2_one_y = G2::one().Y;

    libff::alt_bn128_Fq2 fq2_in_x;
    {
        std::istringstream ss(hex_to_bin(fq2_x_string));
        read_powersoftau_fq2(ss, fq2_in_x);
    }

    libff::alt_bn128_Fq2 fq2_in_y;
    {
        std::istringstream ss(hex_to_bin(fq2_y_string));
        read_powersoftau_fq2(ss, fq2_in_y);
    }

    std::string g2_one_x_write;
    {
        std::ostringstream out;
        write_powersoftau_fq2(out, g2_one_x);
        g2_one_x_write = bin_to_hex(out.str());
    }

    std::cout << "fq2_in_x hex (full): " << std::endl
              << to_hex(fq2_in_x) << std::endl;
    std::cout << "fq2_in_y hex (full): " << std::endl
              << to_hex(fq2_in_y) << std::endl;

    ASSERT_EQ(g2_one_x, fq2_in_x);
    ASSERT_EQ(g2_one_y, fq2_in_y);
    ASSERT_EQ(fq2_x_string, g2_one_x_write);
}

TEST(PowersOfTauTests, ReadWritePowersOfTauG2)
{
    const Fr fr_1 = Fr::one();
    const Fr fr_2 = fr_1 + fr_1;
    const Fr fr_4 = fr_2 + fr_2;
    const Fr fr_7 = fr_4 + fr_2 + fr_1;
    const Fr fr_7_inv = fr_7.inverse();
    const G2 g2_7_inv = fr_7_inv * G2::one();

    const std::string s_g2_0 = "00";
    const std::string s_g2_1 =
        "04"
        "04d4bf3239f77cee7b47c7245e9281b3e9c1182d6381a87bbf81f9f2a6254b73"
        "1df569cda95e060bee91ba69b3f2d103658a7aea6b10e5bdc761e5715e7ee4bb"
        "01b4c328f0cbdb4aada63b3d09100d792376b94d07a6004e46054eeec849e8de"
        "9835158a11d28483dd8db236ea49f3630edc9e41944e494c5aacfc36af3b66e7";
    const std::string s_g2_7_inv =
        "04"
        "01e7e3104c91291acf280deb0a4cd382378e7a8ef1bd689acb043228e8b43124"
        "b85ceb754819742ae483c87d54b6e7ed757faf6554923b63de6785e5cc97c837"
        "08f37b607f92d68a476f98faa3d239b199e291263f4e82266aa2c71c2e9b7e5f"
        "b14da6d95df90f1f022fad41d223e50698a91e5d7f74dce6a77d752b8ab81a64";

    const G2 g2_1 = G2::one();
    const G2 g2_1_read = pot_hex_to_g2(s_g2_1);
    const G2 g2_7_inv_read = pot_hex_to_g2(s_g2_7_inv);

    std::cout << "g2_1_read (2 components): " << std::endl
              << to_hex(g2_1_read.X) << std::endl
              << to_hex(g2_1_read.Y) << std::endl;
    std::cout << "g2_1 (2 components): " << std::endl
              << to_hex(g2_1.X) << std::endl
              << to_hex(g2_1.Y) << std::endl;

    std::string g2_7_inv_write;
    {
        std::ostringstream out;
        write_powersoftau_g2(out, g2_7_inv);
        g2_7_inv_write = bin_to_hex(out.str());
    }

    ASSERT_EQ(G2::zero(), pot_hex_to_g2(s_g2_0));
    ASSERT_EQ(g2_1.X, g2_1_read.X);
    ASSERT_EQ(g2_1.Y, g2_1_read.Y);
    ASSERT_EQ(g2_1.Z, g2_1_read.Z);
    ASSERT_EQ(G2::one(), g2_1_read);
    ASSERT_EQ(g2_7_inv, g2_7_inv_read);
    ASSERT_EQ(s_g2_7_inv, g2_7_inv_write);
}

TEST(PowersOfTauTests, ReadWritePowersOfTauOutput)
{
    fs::path filename = g_testdata_dir / "powersoftau_challenge.4.bin";
    const size_t n = 16;

    std::ifstream in(
        filename.c_str(), std::ios_base::binary | std::ios_base::in);
    srs_powersoftau<ppT> pot = powersoftau_load(in, n);

    std::string expect_pot_write;
    {
        std::ifstream in_pot(
            filename.c_str(), std::ios_base::binary | std::ios_base::in);
        expect_pot_write = std::string(
            std::istreambuf_iterator<char>(in_pot),
            std::istreambuf_iterator<char>());
    }

    std::string pot_write;
    {
        std::ostringstream out;
        powersoftau_write(out, pot);
        pot_write = out.str();

        // powersoftau_write creates a dummy hash at the start, which may not
        // match the original, so extract the substring to be compared.
        pot_write = pot_write.substr(64);
    }

    ASSERT_TRUE(powersoftau_is_well_formed(pot));
    ASSERT_EQ(expect_pot_write.substr(64, pot_write.size()), pot_write);
}

TEST(PowersOfTauTests, ComputeLagrangeEvaluation)
{
    const size_t n = 16;

    // dummy phase 1
    Fr tau = Fr::random_element();
    Fr alpha = Fr::random_element();
    Fr beta = Fr::random_element();
    const srs_powersoftau<ppT> pot =
        dummy_powersoftau_from_secrets<ppT>(tau, alpha, beta, n);
    const srs_lagrange_evaluations<ppT> lagrange =
        powersoftau_compute_lagrange_evaluations(pot, n);

    // Compare to the naive evaluations obtained using iFFT in Fr, and
    // evaluating the polynomial.
    libfqfft::basic_radix2_domain<Fr> domain(n);
    evaluator_from_lagrange<ppT, G1> eval_g1(pot.tau_powers_g1, domain);
    evaluator_from_lagrange<ppT, G2> eval_g2(pot.tau_powers_g2, domain);
    evaluator_from_lagrange<ppT, G1> eval_alpha_g1(
        pot.alpha_tau_powers_g1, domain);
    evaluator_from_lagrange<ppT, G1> eval_beta_g1(
        pot.beta_tau_powers_g1, domain);

    for (size_t j = 0; j < n; ++j) {
        printf("j=%zu\n", j);
        std::map<size_t, Fr> l_factors;
        l_factors[j] = Fr::one();

        G1 L_j_g1 = eval_g1.evaluate_from_lagrange_factors(l_factors);
        ASSERT_EQ(L_j_g1, lagrange.lagrange_g1[j])
            << "L_" << std::to_string(j) << " in G1";

        G2 L_j_g2 = eval_g2.evaluate_from_lagrange_factors(l_factors);
        ASSERT_EQ(L_j_g2, lagrange.lagrange_g2[j])
            << "L_" << std::to_string(j) << " in G2";

        G1 alpha_L_j_g1 =
            eval_alpha_g1.evaluate_from_lagrange_factors(l_factors);
        ASSERT_EQ(alpha_L_j_g1, lagrange.alpha_lagrange_g1[j])
            << "alpha L_" << std::to_string(j) << " in G1";

        G1 beta_L_j_g1 = eval_beta_g1.evaluate_from_lagrange_factors(l_factors);
        ASSERT_EQ(beta_L_j_g1, lagrange.beta_lagrange_g1[j])
            << "beta L_" << std::to_string(j) << " in G1";
    }
}

TEST(PowersOfTauTests, SerializeG2)
{
    const Fr fr_7(7);
    const G2 g2_7 = fr_7 * G2::one();

    std::cout << "g2_7: " << to_hex(g2_7) << std::endl;

    // Serialize
    std::ostringstream out;
    out << g2_7;
    std::string g2_7_ser = out.str();
    std::cout << "g2_7_ser: " << bin_to_hex(g2_7_ser) << std::endl;

    // Deserialize
    std::istringstream in(g2_7_ser);
    G2 g2_7_deser;
    in >> g2_7_deser;

    ASSERT_EQ(g2_7, g2_7_deser);
}

TEST(PowersOfTauTests, SerializeLagrangeEvaluation)
{
    const size_t n = 16;
    const srs_powersoftau<ppT> pot = dummy_powersoftau<ppT>(n);
    const srs_lagrange_evaluations<ppT> lagrange =
        powersoftau_compute_lagrange_evaluations(pot, n);

    std::ostringstream out;
    lagrange.write(out);
    std::string lagrange_ser = out.str();

    std::istringstream in(lagrange_ser);
    const srs_lagrange_evaluations<ppT> lagrange_deser =
        srs_lagrange_evaluations<ppT>::read(in);

    ASSERT_EQ(lagrange.degree, lagrange_deser.degree);
    ASSERT_EQ(lagrange.lagrange_g1, lagrange_deser.lagrange_g1);
    ASSERT_EQ(lagrange.lagrange_g2, lagrange_deser.lagrange_g2);
    ASSERT_EQ(lagrange.alpha_lagrange_g1, lagrange_deser.alpha_lagrange_g1);
    ASSERT_EQ(lagrange.beta_lagrange_g1, lagrange_deser.beta_lagrange_g1);
}

TEST(PowersOfTauTests, G1PointCompression)
{
    auto check_g1_compressed = [](const G1 &v) {
        const size_t expectCompressedSize = 33;
        check_point_serialization<
            G1,
            expectCompressedSize,
            libff::alt_bn128_G1_write_compressed,
            libff::alt_bn128_G1_read_compressed>(v);
    };

    auto check_g1_uncompressed = [](const G1 &v) {
        const size_t expectUncompressedSize = 65;
        check_point_serialization<
            G1,
            expectUncompressedSize,
            libff::alt_bn128_G1_write_uncompressed,
            libff::alt_bn128_G1_read_uncompressed>(v);
    };

    auto check_g1 = [&](const G1 &v) {
        check_g1_compressed(v);
        check_g1_uncompressed(v);
    };

    check_g1(G1::zero());
    check_g1(G1::one());
    check_g1(Fr(7).inverse() * G1::one());
    check_g1(Fr(-1) * Fr(7).inverse() * G1::one());
}

TEST(PowersOfTauTests, G2PointCompression)
{
    auto check_g2_compressed = [](const G2 &v) {
        const size_t expectCompressedSize = 65;
        check_point_serialization<
            G2,
            expectCompressedSize,
            libff::alt_bn128_G2_write_compressed,
            libff::alt_bn128_G2_read_compressed>(v);
    };

    auto check_g2_uncompressed = [](const G2 &v) {
        const size_t expectUncompressedSize = 129;
        check_point_serialization<
            G2,
            expectUncompressedSize,
            libff::alt_bn128_G2_write_uncompressed,
            libff::alt_bn128_G2_read_uncompressed>(v);
    };

    auto check_g2 = [&](const G2 &v) {
        check_g2_compressed(v);
        check_g2_uncompressed(v);
    };

    check_g2(G2::zero());
    check_g2(G2::one());
    check_g2(Fr(7).inverse() * G2::one());
    check_g2(Fr(-1) * Fr(7).inverse() * G2::one());
}

} // namespace

int main(int argc, char **argv)
{
    // !!! WARNING: Do not forget to do this once for all tests !!!
    ppT::init_public_params();

    // Remove stdout noise from libff
    libff::inhibit_profiling_counters = true;
    libff::inhibit_profiling_info = true;

    ::testing::InitGoogleTest(&argc, argv);

    // Extract the testdata dir, if passed on the command line.
    if (argc > 1) {
        g_testdata_dir = fs::path(argv[1]) / "testdata";
    } else {
        const char *const zeth = getenv("ZETH");
        if (zeth != nullptr) {
            g_testdata_dir = fs::path(zeth) / "testdata";
        }
    }

    return RUN_ALL_TESTS();
}
