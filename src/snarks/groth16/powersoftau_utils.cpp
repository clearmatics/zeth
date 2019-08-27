#include "powersoftau_utils.hpp"

#include <thread>

namespace libzeth
{

namespace
{

// Utility functions

// Use the technique described in Section 3 of "A multi-party protocol
// for constructing the public parameters of the Pinocchio zk-SNARK"
// to efficiently evaluate Lagrange polynomials ${L_i(x)}_i$ for the
// $d=2^n$-roots of unity, given powers ${x^i}_i$ for $i=0..d-1$.
template<typename Fr, typename Gr>
static void compute_lagrange_from_powers(
    std::vector<Gr> &powers, const Fr &omega_inv)
{
    libfqfft::_basic_radix2_FFT<Fr, Gr>(powers, omega_inv);
    const Fr n_inv = Fr(powers.size()).inverse();
    for (auto &a : powers) {
        a = n_inv * a;
    }
}

class membuf : public std::streambuf
{
public:
    membuf(char *begin, char *end) { this->setg(begin, begin, end); }
};

template<mp_size_t n, const libff::bigint<n> &modulus>
std::istream &read_powersoftau_fp(
    std::istream &in, libff::Fp_model<n, modulus> &out)
{
    const size_t data_size = sizeof(libff::bigint<n>);
    char tmp[data_size];
    in.read(tmp, data_size);
    std::reverse(&tmp[0], &tmp[data_size]);
    membuf fq_stream(tmp, &tmp[data_size]);
    std::istream(&fq_stream) >> out;
    return in;
}

template<mp_size_t n, const libff::bigint<n> &modulus>
std::istream &read_powersoftau_fp2(
    std::istream &in, libff::Fp2_model<n, modulus> &el)
{
    // Fq2 data is packed into a single 512 bit integer as:
    //
    //   c1 * modulus + c0
    libff::bigint<2 * n> packed;
    in >> packed;
    std::reverse((uint8_t *)&packed, (uint8_t *)((&packed) + 1));

    libff::bigint<n + 1> c1;

    mpn_tdiv_qr(
        c1.data,              // quotient
        el.c0.mont_repr.data, // remainder
        0,
        packed.data,
        n * 2,
        modulus.data,
        n);

    for (size_t i = 0; i < n; ++i) {
        el.c1.mont_repr.data[i] = c1.data[i];
    }
    el.c0.mul_reduce(libff::Fp_model<n, modulus>::Rsquared);
    el.c1.mul_reduce(libff::Fp_model<n, modulus>::Rsquared);

    return in;
}

} // namespace

using ppT = libff::default_ec_pp;
using Fr = libff::Fr<ppT>;
using G1 = libff::G1<ppT>;
using G2 = libff::G2<ppT>;

template<typename ppT>
bool same_ratio(
    const libff::G1<ppT> &a1,
    const libff::G1<ppT> &b1,
    const libff::G2<ppT> &a2,
    const libff::G2<ppT> &b2)
{
    const libff::G1_precomp<ppT> &a1_precomp = ppT::precompute_G1(a1);
    const libff::G1_precomp<ppT> &b1_precomp = ppT::precompute_G1(b1);
    const libff::G2_precomp<ppT> &a2_precomp = ppT::precompute_G2(a2);
    const libff::G2_precomp<ppT> &b2_precomp = ppT::precompute_G2(b2);

    const libff::Fqk<ppT> a1b2 = ppT::miller_loop(a1_precomp, b2_precomp);
    const libff::Fqk<ppT> b1a2 = ppT::miller_loop(b1_precomp, a2_precomp);

    const libff::GT<ppT> a1b2_gt = ppT::final_exponentiation(a1b2);
    const libff::GT<ppT> b1a2_gt = ppT::final_exponentiation(b1a2);

    // Decide whether ratio a1:b1 in G1 equals a2:b2 in G2 by checking:
    //   e(a1, b2) =?= e(b1, a2)
    return a1b2_gt == b1a2_gt;
}

// -----------------------------------------------------------------------------
// powersoftau
// -----------------------------------------------------------------------------

srs_powersoftau::srs_powersoftau(
    libff::G1_vector<ppT> &&tau_powers_g1,
    libff::G2_vector<ppT> &&tau_powers_g2,
    libff::G1_vector<ppT> &&alpha_tau_powers_g1,
    libff::G1_vector<ppT> &&beta_tau_powers_g1,
    const libff::G2<ppT> &beta_g2)
    : tau_powers_g1(std::move(tau_powers_g1))
    , tau_powers_g2(std::move(tau_powers_g2))
    , alpha_tau_powers_g1(std::move(alpha_tau_powers_g1))
    , beta_tau_powers_g1(std::move(beta_tau_powers_g1))
    , beta_g2(beta_g2)
{
}

srs_powersoftau dummy_powersoftau_from_secrets(
    const Fr &tau, const Fr &alpha, const Fr &beta, size_t n)
{
    libff::enter_block("dummy_phase1_from_secrets");

    // Compute powers.  Note zero-th power is included (alpha_g1 etc
    // are provided in this way), so to support order N polynomials,
    // N+1 entries are required.
    const size_t num_tau_powers_g1 = 2 * n - 2 + 1;
    libff::G1_vector<ppT> tau_powers_g1;
    libff::G2_vector<ppT> tau_powers_g2;
    libff::G1_vector<ppT> alpha_tau_powers_g1;
    libff::G1_vector<ppT> beta_tau_powers_g1;

    libff::enter_block("tau powers");
    std::vector<Fr> tau_powers(num_tau_powers_g1);
    tau_powers[0] = Fr::one();
    for (size_t i = 1; i < num_tau_powers_g1; ++i) {
        tau_powers[i] = tau * tau_powers[i - 1];
    }
    libff::leave_block("tau powers");

    libff::enter_block("window tables");
    const size_t window_size = libff::get_exp_window_size<G1>(n);
    const size_t window_size_tau_g1 = libff::get_exp_window_size<G1>(2 * n - 1);

    libff::window_table<libff::G1<ppT>> tau_g1_table;
    libff::window_table<libff::G2<ppT>> tau_g2_table;
    libff::window_table<libff::G1<ppT>> alpha_tau_g1_table;
    libff::window_table<libff::G1<ppT>> beta_tau_g1_table;
    {
        std::thread tau_g1_table_thread([&tau_g1_table, window_size_tau_g1]() {
            tau_g1_table = libff::get_window_table(
                libff::G1<ppT>::size_in_bits(), window_size_tau_g1, G1::one());
        });

        std::thread tau_g2_table_thread([&tau_g2_table, window_size]() {
            tau_g2_table = libff::get_window_table(
                libff::G2<ppT>::size_in_bits(), window_size, G2::one());
        });

        std::thread alpha_tau_g1_table_thread([&alpha_tau_g1_table,
                                               window_size,
                                               alpha]() {
            alpha_tau_g1_table = libff::get_window_table(
                libff::G1<ppT>::size_in_bits(), window_size, alpha * G1::one());
        });

        std::thread beta_tau_g1_table_thread([&beta_tau_g1_table,
                                              window_size,
                                              beta]() {
            beta_tau_g1_table = libff::get_window_table(
                libff::G1<ppT>::size_in_bits(), window_size, beta * G1::one());
        });

        tau_g1_table_thread.join();
        tau_g2_table_thread.join();
        alpha_tau_g1_table_thread.join();
        beta_tau_g1_table_thread.join();
    }
    libff::leave_block("window tables");

    libff::enter_block("tau_g1 powers");
    tau_powers_g1 = libff::batch_exp(
        libff::G1<ppT>::size_in_bits(),
        window_size_tau_g1,
        tau_g1_table,
        tau_powers);
    libff::leave_block("tau_g1 powers");

    libff::enter_block("tau_g2 powers");
    tau_powers_g2 = libff::batch_exp(
        libff::G2<ppT>::size_in_bits(),
        window_size,
        tau_g2_table,
        tau_powers,
        n);
    libff::leave_block("tau_g2 powers");

    libff::enter_block("alpha_tau_g1 powers");
    alpha_tau_powers_g1 = libff::batch_exp(
        libff::G1<ppT>::size_in_bits(),
        window_size,
        alpha_tau_g1_table,
        tau_powers,
        n);
    libff::leave_block("alpha_tau_g1 powers");

    libff::enter_block("beta_tau_g1 powers");
    beta_tau_powers_g1 = libff::batch_exp(
        libff::G1<ppT>::size_in_bits(),
        window_size,
        beta_tau_g1_table,
        tau_powers,
        n);
    libff::leave_block("beta_tau_g1 powers");

    libff::leave_block("dummy_phase1_from_secrets");
    return srs_powersoftau(
        std::move(tau_powers_g1),
        std::move(tau_powers_g2),
        std::move(alpha_tau_powers_g1),
        std::move(beta_tau_powers_g1),
        beta * G2::one());
}

srs_powersoftau dummy_powersoftau(size_t n)
{
    Fr tau = Fr::random_element();
    Fr alpha = Fr::random_element();
    Fr beta = Fr::random_element();

    return dummy_powersoftau_from_secrets(tau, alpha, beta, n);
}

void read_powersoftau_fr(std::istream &in, libff::Fr<ppT> &out)
{
    read_powersoftau_fp(in, out);
}

void read_powersoftau_g1(std::istream &in, libff::G1<ppT> &out)
{
    uint8_t marker;
    in.read((char *)&marker, 1);

    switch (marker) {
    case 0x00:
        // zero
        out = libff::G1<ppT>::zero();
        break;
    case 0x04: {
        // Uncompressed
        libff::Fq<ppT> x;
        libff::Fq<ppT> y;
        read_powersoftau_fp(in, x);
        read_powersoftau_fp(in, y);
        out = libff::G1<ppT>(x, y, libff::Fq<ppT>::one());
        break;
    }
    default:
        assert(false);
        break;
    }
}

void read_powersoftau_fq2(std::istream &in, libff::alt_bn128_Fq2 &out)
{
    read_powersoftau_fp2(in, out);
}

void read_powersoftau_g2(std::istream &in, libff::G2<ppT> &out)
{
    uint8_t marker;
    in.read((char *)&marker, 1);

    switch (marker) {
    case 0x00:
        // zero
        out = libff::G2<ppT>::zero();
        break;

    case 0x04:
        // Uncompressed
        read_powersoftau_fp2(in, out.X);
        read_powersoftau_fp2(in, out.Y);
        out.Z = libff::alt_bn128_Fq2::one();
        break;

    default:
        assert(false);
        break;
    }
}

srs_powersoftau powersoftau_load(std::istream &in, size_t n)
{
    // From:
    //
    //   https://github.com/clearmatics/powersoftau
    //
    // Assume the stream is the final response file from the
    // powersoftau protocol.  Load the Accumulator object.
    //
    // File is structured:
    //
    //   [prev_hash    : uint8_t[64]]
    //   [accumulator  : Accumulator]
    //   [contribution : Public Key ]
    //
    // From src/lib.rs:
    //
    //   pub struct Accumulator {
    //     /// tau^0, tau^1, tau^2, ..., tau^{TAU_POWERS_G1_LENGTH - 1}
    //     pub tau_powers_g1: Vec<G1>,
    //     /// tau^0, tau^1, tau^2, ..., tau^{TAU_POWERS_LENGTH - 1}
    //     pub tau_powers_g2: Vec<G2>,
    //     /// alpha * tau^0, alpha * tau^1, alpha * tau^2, ..., alpha *
    //     tau^{TAU_POWERS_LENGTH - 1} pub alpha_tau_powers_g1: Vec<G1>,
    //     /// beta * tau^0, beta * tau^1, beta * tau^2, ..., beta *
    //     tau^{TAU_POWERS_LENGTH - 1} pub beta_tau_powers_g1: Vec<G1>,
    //     /// beta
    //     pub beta_g2: G2
    //   }
    uint8_t hash[64];
    in.read((char *)(&hash[0]), sizeof(hash));

    const size_t num_powers_of_tau = 2 * n - 1;

    std::vector<G1> tau_powers_g1(num_powers_of_tau);
    for (size_t i = 0; i < num_powers_of_tau; ++i) {
        read_powersoftau_g1(in, tau_powers_g1[i]);
    }

    std::vector<G2> tau_powers_g2(n);
    for (size_t i = 0; i < n; ++i) {
        read_powersoftau_g2(in, tau_powers_g2[i]);
    }

    std::vector<G1> alpha_tau_powers_g1(n);
    for (size_t i = 0; i < n; ++i) {
        read_powersoftau_g1(in, alpha_tau_powers_g1[i]);
    }

    std::vector<G1> beta_tau_powers_g1(n);
    for (size_t i = 0; i < n; ++i) {
        read_powersoftau_g1(in, beta_tau_powers_g1[i]);
    }

    G2 beta_g2;
    read_powersoftau_g2(in, beta_g2);

    return srs_powersoftau(
        std::move(tau_powers_g1),
        std::move(tau_powers_g2),
        std::move(alpha_tau_powers_g1),
        std::move(beta_tau_powers_g1),
        beta_g2);
}

bool powersoftau_validate(const srs_powersoftau &pot, const size_t n)
{
    // TODO: Cache precomputed g1, tau_g1, g2, tau_g2
    // TODO: Parallelize

    // Make sure that the identity of each group is at index 0
    if (pot.tau_powers_g1[0] != G1::one() ||
        pot.tau_powers_g2[0] != G2::one()) {
        return false;
    }

    const size_t num_tau_powers_g1 = 2 * n - 1;
    const G1 g1 = G1::one();
    const G2 g2 = G2::one();
    const G1 tau_g1 = pot.tau_powers_g1[1];
    const G2 tau_g2 = pot.tau_powers_g2[1];

    // SameRatio((g1, tau_g1), (g2, tau_g2))
    const bool tau_g1_g2_consistent =
        same_ratio<ppT>(g1, pot.tau_powers_g1[1], g2, pot.tau_powers_g2[1]);
    if (!tau_g1_g2_consistent) {
        return false;
    }

    // TODO: This can be done probabilistically with (faster) random
    // linear combinations.

    // SameRatio((tau_powers_g1[i-1], tau_powers_g1[i]), (g2, tau_g2))
    // SameRatio((tau_powers_g2[i-1], tau_powers_g2[i]), (g1, tau_g1))
    // SameRatio(
    //     (alpha_tau_powers_g1[i-1], alpha_tau_powers_g1[i]), (g2, tau_g2))
    // SameRatio(
    //     (beta_tau_powers_g1[i-1], beta_tau_powers_g1[i]), (g2, tau_g2))
    for (size_t i = 1; i < n; ++i) {
        if (!same_ratio<ppT>(
                pot.tau_powers_g1[i - 1], pot.tau_powers_g1[i], g2, tau_g2) ||
            !same_ratio<ppT>(
                g1, tau_g1, pot.tau_powers_g2[i - 1], pot.tau_powers_g2[i]) ||
            !same_ratio<ppT>(
                pot.alpha_tau_powers_g1[i - 1],
                pot.alpha_tau_powers_g1[i],
                g2,
                tau_g2) ||
            !same_ratio<ppT>(
                pot.beta_tau_powers_g1[i - 1],
                pot.beta_tau_powers_g1[i],
                g2,
                tau_g2)) {
            return false;
        }
    }

    // SameRatio((tau_powers_g1[i-1], tau_powers_g1[i]), (g2, tau_g2))
    // for remaining powers
    for (size_t i = n; i < num_tau_powers_g1; ++i) {
        if (!same_ratio<ppT>(
                pot.tau_powers_g1[i - 1], pot.tau_powers_g1[i], g2, tau_g2)) {
            return false;
        }
    }

    // SameRatio((g1, beta_tau_powers_g1), (g2, beta_g2))
    // SameRatio((g1, delta_g1), (g2, delta_g2))
    if (!same_ratio<ppT>(g1, pot.beta_tau_powers_g1[0], g2, pot.beta_g2)) {
        return false;
    }

    return true;
}

// -----------------------------------------------------------------------------
// powersoftau_lagrange_evaluations
// -----------------------------------------------------------------------------

srs_lagrange_evaluations::srs_lagrange_evaluations(
    size_t degree,
    std::vector<G1> &&lagrange_g1,
    std::vector<G2> &&lagrange_g2,
    std::vector<G1> &&alpha_lagrange_g1,
    std::vector<G1> &&beta_lagrange_g1)
    : degree(degree)
    , lagrange_g1(std::move(lagrange_g1))
    , lagrange_g2(std::move(lagrange_g2))
    , alpha_lagrange_g1(std::move(alpha_lagrange_g1))
    , beta_lagrange_g1(std::move(beta_lagrange_g1))
{
}

srs_lagrange_evaluations powersoftau_compute_lagrange_evaluations(
    const srs_powersoftau &pot, const size_t n)
{
    using Fr = libff::Fr<ppT>;
    using G1 = libff::G1<ppT>;
    using G2 = libff::G2<ppT>;

    if (n != 1ull << libff::log2(n)) {
        throw std::invalid_argument("non-pow-2 domain");
    }
    if (pot.tau_powers_g1.size() < n) {
        throw std::invalid_argument("insufficient powers of tau");
    }

    libff::enter_block("r1cs_gg_ppzksnark_compute_lagrange_evaluations");
    libff::print_indent();
    printf("n=%zu\n", n);

    libfqfft::basic_radix2_domain<Fr> domain(n);
    const Fr omega = domain.get_domain_element(1);
    const Fr omega_inv = omega.inverse();

    // Compute [ L_j(t) ]_1 from { [x^i] } i=0..n-1
    libff::enter_block("computing [Lagrange_i(x)]_1");
    std::vector<G1> lagrange_g1(
        pot.tau_powers_g1.begin(), pot.tau_powers_g1.begin() + n);
    assert(lagrange_g1[0] == G1::one());
    assert(lagrange_g1.size() == n);
    compute_lagrange_from_powers(lagrange_g1, omega_inv);
    libff::leave_block("computing [Lagrange_i(x)]_1");

    libff::enter_block("computing [Lagrange_i(x)]_2");
    std::vector<G2> lagrange_g2(
        pot.tau_powers_g2.begin(), pot.tau_powers_g2.begin() + n);
    assert(lagrange_g2[0] == G2::one());
    assert(lagrange_g2.size() == n);
    compute_lagrange_from_powers(lagrange_g2, omega_inv);
    libff::leave_block("computing [Lagrange_i(x)]_2");

    libff::enter_block("computing [alpha . Lagrange_i(x)]_1");
    std::vector<G1> alpha_lagrange_g1(
        pot.alpha_tau_powers_g1.begin(), pot.alpha_tau_powers_g1.begin() + n);
    assert(alpha_lagrange_g1.size() == n);
    compute_lagrange_from_powers(alpha_lagrange_g1, omega_inv);
    libff::leave_block("computing [alpha . Lagrange_i(x)]_1");

    libff::enter_block("computing [beta . Lagrange_i(x)]_1");
    std::vector<G1> beta_lagrange_g1(
        pot.beta_tau_powers_g1.begin(), pot.beta_tau_powers_g1.begin() + n);
    assert(beta_lagrange_g1.size() == n);
    compute_lagrange_from_powers(beta_lagrange_g1, omega_inv);
    libff::leave_block("computing [beta . Lagrange_i(x)]_1");

    libff::leave_block("r1cs_gg_ppzksnark_compute_lagrange_evaluations");

    return srs_lagrange_evaluations(
        n,
        std::move(lagrange_g1),
        std::move(lagrange_g2),
        std::move(alpha_lagrange_g1),
        std::move(beta_lagrange_g1));
}

} // namespace libzeth
