
#include "powersoftau_utils.hpp"

namespace libzeth
{

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
    //   e( a1, b2 ) == e( b1, a2 )
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
    // Compute powers.  Note zero-th power is included (alpha_g1 etc
    // are provided in this way), so to support order N polynomials,
    // N+1 entries are required.
    const size_t num_tau_powers_g1 = 2 * n - 2 + 1;
    libff::G1_vector<ppT> tau_powers_g1(num_tau_powers_g1);
    libff::G2_vector<ppT> tau_powers_g2(n);
    libff::G1_vector<ppT> alpha_tau_powers_g1(n);
    libff::G1_vector<ppT> beta_tau_powers_g1(n);

    tau_powers_g1[0] = G1::one();
    tau_powers_g2[0] = G2::one();
    alpha_tau_powers_g1[0] = alpha * G1::one();
    beta_tau_powers_g1[0] = beta * G1::one();

    for (size_t i = 1; i < n; ++i) {
        tau_powers_g1[i] = tau * tau_powers_g1[i - 1];
        tau_powers_g2[i] = tau * tau_powers_g2[i - 1];
        alpha_tau_powers_g1[i] = tau * alpha_tau_powers_g1[i - 1];
        beta_tau_powers_g1[i] = tau * beta_tau_powers_g1[i - 1];
    }

    for (size_t i = n; i < num_tau_powers_g1; ++i) {
        tau_powers_g1[i] = tau * tau_powers_g1[i - 1];
    }

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

bool powersoftau_validate(const srs_powersoftau &pot, const size_t n)
{
    // TODO: Cache precomputed g1, tau_g1, g2, tau_g2
    // TODO: Parallelize

    // One at index 0
    if (pot.tau_powers_g1[0] != G1::one() ||
        pot.tau_powers_g2[0] != G2::one()) {
        return false;
    }

    const size_t num_tau_powers_g1 = 2 * n - 1;
    const G1 g1 = G1::one();
    const G2 g2 = G2::one();
    const G1 tau_g1 = pot.tau_powers_g1[1];
    const G2 tau_g2 = pot.tau_powers_g2[1];

    // SameRatio( (g1, tau_g1), (g2, tau_g2) )
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

} // namespace libzeth
