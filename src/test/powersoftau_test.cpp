
#include "snarks/groth16/evaluator_from_lagrange.hpp"
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
    const srs_powersoftau<ppT> pot = dummy_powersoftau<ppT>(n);

    ASSERT_TRUE(powersoftau_validate(pot, n));

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

        ASSERT_FALSE(powersoftau_validate(tamper_tau_g1, n));
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

        ASSERT_FALSE(powersoftau_validate(tamper_tau_g2, n));
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

        ASSERT_FALSE(powersoftau_validate(tamper_alpha_tau_g1, n));
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

        ASSERT_FALSE(powersoftau_validate(tamper_beta_tau_g1, n));
    }

    {
        const srs_powersoftau<ppT> tamper_beta_g2(
            libff::G1_vector<ppT>(pot.tau_powers_g1),
            libff::G2_vector<ppT>(pot.tau_powers_g2),
            libff::G1_vector<ppT>(pot.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(pot.beta_tau_powers_g1),
            pot.beta_g2 + G2::one());

        ASSERT_FALSE(powersoftau_validate(tamper_beta_g2, n));
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

    ASSERT_EQ(G1::zero(), hex_to_g1(s_g1_0));
    ASSERT_EQ(G1::one(), hex_to_g1(s_g1_1));
    ASSERT_EQ(expect_g1_7_inv, hex_to_g1(s_g1_7_inv));
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
    const G2 g2_1_read = hex_to_g2(s_g2_1);
    const G2 g2_7_inv_read = hex_to_g2(s_g2_7_inv);

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

    ASSERT_EQ(G2::zero(), hex_to_g2(s_g2_0));
    ASSERT_EQ(g2_1.X, g2_1_read.X);
    ASSERT_EQ(g2_1.Y, g2_1_read.Y);
    ASSERT_EQ(g2_1.Z, g2_1_read.Z);
    ASSERT_EQ(G2::one(), g2_1_read);
    ASSERT_EQ(g2_7_inv, g2_7_inv_read);
    ASSERT_EQ(s_g2_7_inv, g2_7_inv_write);
}

TEST(PowersOfTauTests, ReadWritePowersOfTauOutput)
{
    char *zeth = getenv("ZETH");
    const std::string filename = std::string(zeth == nullptr ? "." : zeth) +
                                 "/testdata/powersoftau_response.4.bin";
    const size_t n = 16;

    std::ifstream in(filename, std::ios_base::binary | std::ios_base::in);
    srs_powersoftau<ppT> pot = powersoftau_load(in, n);

    std::string expect_pot_write;
    {
        std::ifstream in_pot(
            filename, std::ios_base::binary | std::ios_base::in);
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

    ASSERT_TRUE(powersoftau_validate(pot, n));
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
