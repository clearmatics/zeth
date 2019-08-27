
#include "snarks/groth16/powersoftau_utils.hpp"
#include "util.hpp"

#include <fstream>
#include <gtest/gtest.h>

using ppT = libff::default_ec_pp;
using Fr = libff::Fr<ppT>;
using G1 = libff::G1<ppT>;
using G2 = libff::G2<ppT>;
using namespace libsnark;
using namespace libzeth;

namespace
{

static std::string hex_to_bin(const std::string &hex)
{
    return hexadecimal_str_to_binary_str(hex);
}

static std::string bin_to_hex(const std::string &hex)
{
    return binary_str_to_hexadecimal_str(hex);
}

G1 hex_to_g1(const std::string &s)
{
    const std::string bin = hex_to_bin(s);
    std::istringstream ss_bytes(bin);
    G1 out;
    read_powersoftau_g1(ss_bytes, out);
    return out;
}

G2 hex_to_g2(const std::string hex)
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

TEST(PowersOfTauTests, PowersOfTauValidation)
{
    const size_t n = 16;
    const srs_powersoftau pot = dummy_powersoftau(n);

    ASSERT_TRUE(powersoftau_validate(pot, n));

    // tamper with some individual entries
    {
        libff::G1_vector<ppT> tau_powers_g1 = pot.tau_powers_g1;
        tau_powers_g1[2] = tau_powers_g1[2] + G1::one();
        const srs_powersoftau tamper_tau_g1(
            std::move(tau_powers_g1),
            libff::G2_vector<ppT>(pot.tau_powers_g2),
            libff::G1_vector<ppT>(pot.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(pot.beta_tau_powers_g1),
            pot.beta_g2);

        ASSERT_FALSE(powersoftau_validate(tamper_tau_g1, n));
    }

    {
        libff::G2_vector<ppT> tau_powers_g2 = pot.tau_powers_g2;
        tau_powers_g2[2] = tau_powers_g2[2] + G2::one();
        const srs_powersoftau tamper_tau_g2(
            libff::G1_vector<ppT>(pot.tau_powers_g1),
            std::move(tau_powers_g2),
            libff::G1_vector<ppT>(pot.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(pot.beta_tau_powers_g1),
            pot.beta_g2);

        ASSERT_FALSE(powersoftau_validate(tamper_tau_g2, n));
    }

    {
        libff::G1_vector<ppT> alpha_tau_powers_g1 = pot.alpha_tau_powers_g1;
        alpha_tau_powers_g1[2] = alpha_tau_powers_g1[2] + G1::one();
        const srs_powersoftau tamper_alpha_tau_g1(
            libff::G1_vector<ppT>(pot.tau_powers_g1),
            libff::G2_vector<ppT>(pot.tau_powers_g2),
            std::move(alpha_tau_powers_g1),
            libff::G1_vector<ppT>(pot.beta_tau_powers_g1),
            pot.beta_g2);

        ASSERT_FALSE(powersoftau_validate(tamper_alpha_tau_g1, n));
    }

    {
        libff::G1_vector<ppT> beta_tau_powers_g1 = pot.beta_tau_powers_g1;
        beta_tau_powers_g1[2] = beta_tau_powers_g1[2] + G1::one();
        const srs_powersoftau tamper_beta_tau_g1(
            libff::G1_vector<ppT>(pot.tau_powers_g1),
            libff::G2_vector<ppT>(pot.tau_powers_g2),
            libff::G1_vector<ppT>(pot.alpha_tau_powers_g1),
            std::move(beta_tau_powers_g1),
            pot.beta_g2);

        ASSERT_FALSE(powersoftau_validate(tamper_beta_tau_g1, n));
    }

    {
        const srs_powersoftau tamper_beta_g2(
            libff::G1_vector<ppT>(pot.tau_powers_g1),
            libff::G2_vector<ppT>(pot.tau_powers_g2),
            libff::G1_vector<ppT>(pot.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(pot.beta_tau_powers_g1),
            pot.beta_g2 + G2::one());

        ASSERT_FALSE(powersoftau_validate(tamper_beta_g2, n));
    }
}

TEST(UtilTest, ReadPowersOfTauFr)
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

    ASSERT_EQ(fr_7_inv, fr_7_inv_read);
}

TEST(UtilTest, ReadPowersOfTauG1)
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

    ASSERT_EQ(G1::zero(), hex_to_g1(s_g1_0));
    ASSERT_EQ(G1::one(), hex_to_g1(s_g1_1));
    ASSERT_EQ(expect_g1_7_inv, hex_to_g1(s_g1_7_inv));
}

TEST(UtilTest, ReadPowersOfTauFq2)
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

    std::cout << "fq2_in_x hex (full): " << std::endl
              << to_hex(fq2_in_x) << std::endl;
    std::cout << "fq2_in_y hex (full): " << std::endl
              << to_hex(fq2_in_y) << std::endl;

    ASSERT_EQ(g2_one_x, fq2_in_x);
    ASSERT_EQ(g2_one_y, fq2_in_y);
}

TEST(PowersOfTauTests, ReadPowersOfTauG2)
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
    const G2 g2_1_read = hex_to_g2(s_g2_1);
    const G2 g2_7_inv_read = hex_to_g2(s_g2_7_inv);

    std::cout << "g2_1_read (2 components): " << std::endl
              << to_hex(g2_1_read.X) << std::endl
              << to_hex(g2_1_read.Y) << std::endl;
    std::cout << "g2_1 (2 components): " << std::endl
              << to_hex(g2_1.X) << std::endl
              << to_hex(g2_1.Y) << std::endl;

    ASSERT_EQ(G2::zero(), hex_to_g2(s_g2_0));
    ASSERT_EQ(g2_1.X, g2_1_read.X);
    ASSERT_EQ(g2_1.Y, g2_1_read.Y);
    ASSERT_EQ(g2_1.Z, g2_1_read.Z);
    ASSERT_EQ(G2::one(), g2_1_read);
    ASSERT_EQ(g2_7_inv, g2_7_inv_read);
}

TEST(PowersOfTauTests, ReadPowersOfTauOutput)
{
    char *zeth = getenv("ZETH");
    const std::string filename = std::string(zeth == nullptr ? "." : zeth) +
                                 "/testdata/powersoftau_response.4.bin";
    const size_t n = 16;

    std::ifstream in(filename, std::ios_base::binary | std::ios_base::in);
    srs_powersoftau pot = powersoftau_load(in, n);

    ASSERT_TRUE(powersoftau_validate(pot, n));
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
    return RUN_ALL_TESTS();
}
