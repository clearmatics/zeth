#include "mpc_utils.hpp"

#include "evaluator_from_lagrange.hpp"
#include "multi_exp.hpp"

#include <libff/algebra/scalar_multiplication/multiexp.hpp>

namespace libzeth
{

using ppT = libff::default_ec_pp;
using Fr = libff::Fr<ppT>;
using G1 = libff::G1<ppT>;
using G2 = libff::G2<ppT>;

// -----------------------------------------------------------------------------
// srs_mpc_layer_L1
// -----------------------------------------------------------------------------

srs_mpc_layer_L1::srs_mpc_layer_L1(
    libff::G1_vector<ppT> &&T_tau_powers_g1,
    libff::G1_vector<ppT> &&A_g1,
    libff::G1_vector<ppT> &&B_g1,
    libff::G2_vector<ppT> &&B_g2,
    libff::G1_vector<ppT> &&ABC_g1)
    : T_tau_powers_g1(std::move(T_tau_powers_g1))
    , A_g1(std::move(A_g1))
    , B_g1(std::move(B_g1))
    , B_g2(std::move(B_g2))
    , ABC_g1(std::move(ABC_g1))
{
}

srs_mpc_layer_L1 mpc_compute_linearcombination(
    const srs_powersoftau &pot, const libsnark::qap_instance<Fr> &qap)
{
    libfqfft::evaluation_domain<Fr> &domain = *qap.domain;

    // n = number of constraints in qap / degree of t().
    const size_t n = qap.degree();
    const size_t num_variables = qap.num_variables();

    // Langrange polynomials, and therefore A, B, C will have order
    // (n-1).  T has order n.  H.t() has order 2n-2, => H(.) has
    // order:
    //
    //   2n-2 - n = n-2
    //
    // Therefore { t(x) . x^i } has 0 .. n-2 (n-1 of them), requiring
    // requires powers of tau 0 ..  2.n-2 (2n-1 of them).  We should
    // have at least this many, by definition.

    assert(pot.tau_powers_g1.size() >= 2 * n - 1);

    // n+1 coefficients of t

    std::vector<Fr> t_coefficients(n + 1, Fr::zero());
    qap.domain->add_poly_Z(Fr::one(), t_coefficients);

    // Compute [ t(x) . x^i ]_1 for i = 0 .. n-2

    libff::G1_vector<ppT> t_x_pow_i(n - 1);
    for (size_t i = 0; i < n - 1; ++i) {
        // Use { [x^i] , ... , [x^(i+order_L+1)] } with coefficients
        // of t to compute t(x).x^i.
        t_x_pow_i[i] = multi_exp<ppT, G1>(
            pot.tau_powers_g1.begin() + i,
            pot.tau_powers_g1.begin() + i + n + 1,
            t_coefficients.begin(),
            t_coefficients.end());
    }

    // Compute [ beta.A_i(x) + alpha.B_i(x) + C_i(x) ]_1
    //
    // For each i, get the Lagrange factors of A_i, B_i, C_i.  For
    // each j, if A, B or C has a non-zero factor, grab the Lagrange
    // coefficients, evaluate at [t]_1, multiply by the factor and
    // accumulate.

    libff::G1_vector<ppT> A_i_g1(num_variables + 1);
    libff::G1_vector<ppT> B_i_g1(num_variables + 1);
    libff::G2_vector<ppT> B_i_g2(num_variables + 1);
    libff::G1_vector<ppT> ABC_i_g1(num_variables + 1);

    evaluator_from_lagrange<ppT, G1> tau_eval_g1(pot.tau_powers_g1, domain);
    evaluator_from_lagrange<ppT, G2> tau_eval_g2(pot.tau_powers_g2, domain);
    evaluator_from_lagrange<ppT, G1> alpha_tau_eval(
        pot.alpha_tau_powers_g1, domain);
    evaluator_from_lagrange<ppT, G1> beta_tau_eval(
        pot.beta_tau_powers_g1, domain);

    for (size_t i = 0; i < num_variables + 1; ++i) {
        // Compute [beta.A_i(x)], [alpha.B_i(x)] . [C_i(x)]

        const std::map<size_t, Fr> &A_i_in_lagrange =
            qap.A_in_Lagrange_basis[i];
        const std::map<size_t, Fr> &B_i_in_lagrange =
            qap.B_in_Lagrange_basis[i];
        const std::map<size_t, Fr> &C_i_in_lagrange =
            qap.C_in_Lagrange_basis[i];

        A_i_g1[i] = tau_eval_g1.evaluate_from_lagrange_factors(A_i_in_lagrange);
        B_i_g1[i] = tau_eval_g1.evaluate_from_lagrange_factors(B_i_in_lagrange);
        B_i_g2[i] = tau_eval_g2.evaluate_from_lagrange_factors(B_i_in_lagrange);

        G1 beta_A_at_t =
            beta_tau_eval.evaluate_from_lagrange_factors(A_i_in_lagrange);
        G1 alpha_B_at_t =
            alpha_tau_eval.evaluate_from_lagrange_factors(B_i_in_lagrange);
        G1 C_at_t = tau_eval_g1.evaluate_from_lagrange_factors(C_i_in_lagrange);

        ABC_i_g1[i] = beta_A_at_t + alpha_B_at_t + C_at_t;
    }

    assert(num_variables + 1 == A_i_g1.size());
    assert(num_variables + 1 == B_i_g1.size());
    assert(num_variables + 1 == B_i_g2.size());
    assert(num_variables + 1 == ABC_i_g1.size());

    // TODO: Consider dropping those entries we know will not be used
    // by this circuit and using sparse vectors where it makes sense
    // (as is done for B_i's in r1cs_gg_ppzksnark_proving_key).

    return srs_mpc_layer_L1(
        std::move(t_x_pow_i),
        std::move(A_i_g1),
        std::move(B_i_g1),
        std::move(B_i_g2),
        std::move(ABC_i_g1));
}

} // namespace libzeth
