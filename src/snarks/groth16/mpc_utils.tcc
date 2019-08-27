#ifndef __ZETH_SNARKS_GROTH16_MPC_UTILS_TCC__
#define __ZETH_SNARKS_GROTH16_MPC_UTILS_TCC__

#include "evaluator_from_lagrange.hpp"
#include "mpc_utils.hpp"
#include "multi_exp.hpp"

#include <algorithm>
#include <libff/algebra/scalar_multiplication/multiexp.hpp>

namespace libzeth
{

template<typename T>
static void fill_vector_from_map(
    std::vector<T> &out_vector,
    const std::map<size_t, T> index_map,
    const size_t index_bound)
{
    out_vector.resize(index_bound);
    for (auto &it : index_map) {
        const size_t out_idx = it.first;
        const T &value = it.second;
        if (!value.is_zero()) {
            out_vector[out_idx] = value;
        }
    }
}

template<typename ppT>
srs_mpc_layer_L1<ppT>::srs_mpc_layer_L1(
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

template<typename ppT>
srs_mpc_layer_L1<ppT> mpc_compute_linearcombination(
    const srs_powersoftau &pot,
    const libsnark::qap_instance<libff::Fr<ppT>> &qap)
{
    using Fr = libff::Fr<ppT>;
    using G1 = libff::G1<ppT>;
    using G2 = libff::G2<ppT>;
    libff::enter_block("Call to mpc_compute_linearcombination");

    libfqfft::evaluation_domain<Fr> &domain = *qap.domain;

    // n = number of constraints in r1cs, or equivalently, n = deg(t(x))
    // t(x) being the target polynomial of the QAP
    // Note: In the code-base the target polynomial is also denoted Z
    // as refered to as "the vanishing polynomial", and t is also used
    // to represent the query point (aka "tau").
    const size_t n = qap.degree();
    const size_t num_variables = qap.num_variables();

    // The QAP polynomials A, B, C are of degree (n-1) as we know they
    // are created by interpolation of an r1cs of n constraints.
    // As a consequence, the polynomial (A.B - C) is of degree 2n-2,
    // while the target polynomial t is of degree n.
    // Thus, we need to have access (in the SRS) to powers up to 2n-2.
    // To represent such polynomials we need {x^i} for in {0, ... n-2}
    // hence why we check below that we have at least n-1 elements
    // in the set of powers of tau
    assert(pot.tau_powers_g1.size() >= 2 * n - 1);

    // Number of coefficients to be applied to each power:
    //      num A's + num B's + num C's + (end_t - begin_T)
    //  ~=~ 3 * num A's + (end_t - begin_T)
    const size_t num_scalars_ABC = 3 * num_variables;
    const size_t scalar_size = libff::Fr<ppT>::size_in_bits();

    // n+1 coefficients of
    libff::enter_block("computing coefficients of t()");
    std::vector<Fr> t_coefficients(n + 1, Fr::zero());
    qap.domain->add_poly_Z(Fr::one(), t_coefficients);
    libff::leave_block("computing coefficients of t()");

    // A_coefficients[j][i] is the i-th coefficient of A_j
    libff::enter_block("computing coefficients of QAP polynomials");
    std::vector<std::vector<libff::Fr<ppT>>> A_coefficients(num_variables + 1);
    std::vector<std::vector<libff::Fr<ppT>>> B_coefficients(num_variables + 1);
    std::vector<std::vector<libff::Fr<ppT>>> C_coefficients(num_variables + 1);
    for (size_t j = 0; j < num_variables + 1; ++j) {
        fill_vector_from_map(A_coefficients[j], qap.A_in_Lagrange_basis[j], n);
        domain.iFFT(A_coefficients[j]);

        fill_vector_from_map(B_coefficients[j], qap.B_in_Lagrange_basis[j], n);
        domain.iFFT(B_coefficients[j]);

        fill_vector_from_map(C_coefficients[j], qap.C_in_Lagrange_basis[j], n);
        domain.iFFT(C_coefficients[j]);
    }
    libff::leave_block("computing coefficients of QAP polynomials");

    // For each $i$ in turn, compute the exp table for $[x^i]$ and
    // apply it everywhere, before moving on to the next power.
    libff::enter_block("computing terms for exponentiated powers");
    libff::G1_vector<ppT> t_x_pow_i(n - 1, G1::zero());
    libff::G1_vector<ppT> As_g1(num_variables + 1);
    libff::G1_vector<ppT> Bs_g1(num_variables + 1);
    libff::G2_vector<ppT> Bs_g2(num_variables + 1);
    libff::G1_vector<ppT> ABCs_g1(num_variables + 1);

    for (size_t i = 0; i < 2 * n - 1; ++i) {
        // Compute parameters for window table (see below)
        const size_t begin_T = (size_t)std::max<ssize_t>((ssize_t)i - n, 0);
        const size_t end_T = std::min<size_t>(n - 1, i + 1);

        // Number of coefficients to be applied to each power:
        //        num A's + num B's + num C's + (end_t - begin_T)
        //      ~ 3 * num A's + (end_t - begin_T)
        // For powers i = n, ... there is no coefficient for A, B, C.
        const bool ABC_contributions = i < n;
        const size_t num_scalars =
            (ABC_contributions ? num_scalars_ABC : 0) + end_T - begin_T;
        const size_t window_size = libff::get_exp_window_size<G1>(num_scalars);
        libff::window_table<libff::G1<ppT>> tau_pow_i_table =
            libff::get_window_table(
                scalar_size, window_size, pot.tau_powers_g1[i]);

        // Compute [ t(x) . x^j ]_1 for j = 0 .. n-2
        // Using { [x^j] , ... , [x^(j+n)] } with coefficients
        //                |   t_0   |   t_1   | ..... | t_n
        //   ----------------------------------------------------
        //   t(x).x^0     |   x^0   |   x^1   | ..... | x^n
        //   t(x).x^1     |   x^1   |   x^2   | ..... | x^(n+1)
        //      ...       |    .    |    .    | ..... |  .
        //   t(x).x^(n-2) | x^(n-2) | x^(n-1) | ..... | x^(2n-2)
        //
        // Thereby, $t(x).x^j$ uses $x^i$ with the (i-j)-th coefficient.
        // Or, $x^i$ is used by $t(x).x^j$ for $j =max(i-n, 0), ..., min(n-2,
        // i)$
        for (size_t j = begin_T; j < end_T; ++j) {
            const G1 T_j_contrib = windowed_exp(
                scalar_size,
                window_size,
                tau_pow_i_table,
                t_coefficients[i - j]);
            t_x_pow_i[j] = t_x_pow_i[j] + T_j_contrib;
        }

        if (!ABC_contributions) {
            continue;
        }

        // A, B, C terms (if we are processing a relevant power)
        const size_t ABC_window_size =
            libff::get_exp_window_size<G1>(num_variables);
        libff::window_table<libff::G2<ppT>> tau_pow_i_g2_table =
            libff::get_window_table(
                scalar_size, ABC_window_size, pot.tau_powers_g2[i]);
        libff::window_table<libff::G1<ppT>> alpha_tau_pow_i_g1_table =
            libff::get_window_table(
                scalar_size, ABC_window_size, pot.alpha_tau_powers_g1[i]);
        libff::window_table<libff::G1<ppT>> beta_tau_pow_i_g1_table =
            libff::get_window_table(
                scalar_size, ABC_window_size, pot.beta_tau_powers_g1[i]);

        // Compute i-th term coefficient of each of:
        //   [ A_j(x) ]_1
        //   [ B_n(x) ]_1
        //   [ beta.A_j(x) + alpha.B_j(x) + C_j(x) ]_1
        // for j = 0 ... num_variables
        for (size_t j = 0; j < num_variables + 1; ++j) {
            const Fr A_j_coeff_i = A_coefficients[j][i];
            const Fr B_j_coeff_i = B_coefficients[j][i];
            const Fr C_j_coeff_i = C_coefficients[j][i];

            const G1 A_j_contrib = windowed_exp(
                scalar_size, window_size, tau_pow_i_table, A_j_coeff_i);
            As_g1[j] = As_g1[j] + A_j_contrib;

            const G1 B_j_contrib_g1 = windowed_exp(
                scalar_size, window_size, tau_pow_i_table, B_j_coeff_i);
            Bs_g1[j] = Bs_g1[j] + B_j_contrib_g1;

            const G2 B_j_contrib_g2 = windowed_exp(
                scalar_size, ABC_window_size, tau_pow_i_g2_table, B_j_coeff_i);
            Bs_g2[j] = Bs_g2[j] + B_j_contrib_g2;

            const G1 C_j_contrib = windowed_exp(
                scalar_size, window_size, tau_pow_i_table, C_j_coeff_i);
            const G1 beta_A_j_contrib = windowed_exp(
                scalar_size,
                ABC_window_size,
                beta_tau_pow_i_g1_table,
                A_j_coeff_i);
            const G1 alpha_B_j_contrib = windowed_exp(
                scalar_size,
                ABC_window_size,
                alpha_tau_pow_i_g1_table,
                B_j_coeff_i);
            const G1 ABC_j_contrib =
                beta_A_j_contrib + alpha_B_j_contrib + C_j_contrib;
            ABCs_g1[j] = ABCs_g1[j] + ABC_j_contrib;
        }
    }
    libff::leave_block("computing terms for exponentiated powers");

    // TODO: Consider dropping those entries we know will not be used
    // by this circuit and using sparse vectors where it makes sense
    // (as is done for B_i's in r1cs_gg_ppzksnark_proving_key).
    libff::leave_block("Call to mpc_compute_linearcombination");

    return srs_mpc_layer_L1<ppT>(
        std::move(t_x_pow_i),
        std::move(As_g1),
        std::move(Bs_g1),
        std::move(Bs_g2),
        std::move(ABCs_g1));
}

template<typename ppT>
libsnark::r1cs_gg_ppzksnark_keypair<ppT> mpc_dummy_layer2(
    srs_powersoftau &&pot,
    srs_mpc_layer_L1<ppT> &&layer1,
    const libff::Fr<ppT> &delta,
    libsnark::r1cs_constraint_system<libff::Fr<ppT>> &&cs,
    const libsnark::qap_instance<libff::Fr<ppT>> &qap)
{
    using Fr = libff::Fr<ppT>;
    using G1 = libff::G1<ppT>;
    using G2 = libff::G2<ppT>;

    const Fr delta_inverse = delta.inverse();

    // { H_i } = { [ t(x) . x^i / delta ]_1 } i = 0 .. n-2
    libff::G1_vector<ppT> T_tau_powers_over_delta_g1(
        layer1.T_tau_powers_g1.size());
    for (size_t i = 0; i < layer1.T_tau_powers_g1.size(); ++i) {
        T_tau_powers_over_delta_g1[i] =
            delta_inverse * layer1.T_tau_powers_g1[i];
    }

    // ABC in verification key includes 1 + num_inputs terms.
    // ABC/delta in prover key includes the remaining (num_variables -
    // num_inputs) terms.
    const size_t num_orig_ABC = layer1.ABC_g1.size();
    const size_t num_variables = qap.num_variables();
    const size_t num_inputs = qap.num_inputs();

    assert(num_orig_ABC == num_variables + 1);

    // { ([B_i]_2, [B_i]_1) } i = 0 .. num_orig_ABC
    std::vector<libsnark::knowledge_commitment<G2, G1>> B_i(num_orig_ABC);
    for (size_t i = 0; i < num_orig_ABC; ++i) {
        B_i[i] = libsnark::knowledge_commitment<G2, G1>(
            layer1.B_g2[i], layer1.B_g1[i]);
    }

    assert(B_i.size() == qap.num_variables() + 1);

    // { L_i } = [ { ABC_i / delta } ]_1, i = l+1 .. num_variables
    const size_t num_L_elements = num_variables - num_inputs;
    libff::G1_vector<ppT> L_g1(num_L_elements);
    for (size_t i = num_inputs + 1; i < num_variables + 1; ++i) {
        L_g1[i - num_inputs - 1] = delta_inverse * layer1.ABC_g1[i];
    }
    assert(L_g1.size() == qap.num_variables() - qap.num_inputs());

    // [ ABC_0 ]_1,  { [ABC_i]_1 }, i = 1 .. num_inputs
    G1 ABC_0 = layer1.ABC_g1[0];
    libff::G1_vector<ppT> ABC_i(num_inputs);
    for (size_t i = 0; i < num_inputs; ++i) {
        ABC_i[i] = layer1.ABC_g1[i + 1];
    }

    // Care has been taken above to ensure nothing is used after it's
    // moved, but to be safe, create the vk first (whose constructor
    // does not require a move).
    libsnark::r1cs_gg_ppzksnark_verification_key<ppT> vk(
        pot.alpha_tau_powers_g1[0],
        pot.beta_g2,
        delta * G2::one(),
        libsnark::accumulation_vector<G1>(std::move(ABC_0), std::move(ABC_i)));

    libsnark::r1cs_gg_ppzksnark_proving_key<ppT> pk(
        G1(pot.alpha_tau_powers_g1[0]),
        G1(pot.beta_tau_powers_g1[0]),
        G2(pot.beta_g2),
        delta * G1::one(),
        delta * G2::one(),
        std::move(layer1.A_g1),
        libsnark::knowledge_commitment_vector<G2, G1>(std::move(B_i)),
        std::move(T_tau_powers_over_delta_g1),
        std::move(L_g1),
        std::move(cs));

    return libsnark::r1cs_gg_ppzksnark_keypair<ppT>(
        std::move(pk), std::move(vk));
}

} // namespace libzeth

#endif // __ZETH_SNARKS_GROTH16_MPC_UTILS_TCC__
