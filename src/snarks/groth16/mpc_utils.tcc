#ifndef __ZETH_SNARKS_GROTH16_MPC_UTILS_TCC__
#define __ZETH_SNARKS_GROTH16_MPC_UTILS_TCC__

#include "evaluator_from_lagrange.hpp"
#include "mpc_utils.hpp"
#include "multi_exp.hpp"

#include <algorithm>
#include <exception>
#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libfqfft/evaluation_domain/domains/basic_radix2_domain_aux.tcc>

namespace libzeth
{

template<typename Fr, typename Gr>
static void basic_radix2_iFFT(std::vector<Gr> &as, const Fr &omega_inv)
{
    libfqfft::_basic_radix2_FFT<Fr, Gr>(as, omega_inv);
    const Fr n_inv = Fr(as.size()).inverse();
    for (auto &a : as) {
        a = n_inv * a;
    }
}

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
    libff::print_indent();
    printf("n=%zu\n", n);

    if (n != 1ull << libff::log2(n)) {
        throw std::invalid_argument("non-pow-2 domain");
    }

    const size_t num_variables = qap.num_variables();

    // The QAP polynomials A, B, C are of degree (n-1) as we know they
    // are created by interpolation of an r1cs of n constraints.
    // As a consequence, the polynomial (A.B - C) is of degree 2n-2,
    // while the target polynomial t is of degree n.
    // Thus, we need to have access (in the SRS) to powers up to 2n-2.
    // To represent such polynomials we need {x^i} for in {0, ... n-2}
    // hence we check below that we have at least n-1 elements
    // in the set of powers of tau
    assert(pot.tau_powers_g1.size() >= 2 * n - 1);

    // Number of coefficients to be applied to each power:
    //      num A's + num B's + num C's + (end_t - begin_T)
    //  ~=~ 3 * num A's + (end_t - begin_T)
    const size_t scalar_size = libff::Fr<ppT>::size_in_bits();

    // n+1 coefficients of t
    libff::enter_block("computing coefficients of t()");
    std::vector<Fr> t_coefficients(n + 1, Fr::zero());
    qap.domain->add_poly_Z(Fr::one(), t_coefficients);
    libff::leave_block("computing coefficients of t()");

    const Fr omega = domain.get_domain_element(1);
    const Fr omega_inv = omega.inverse();

    // Compute [ L_j(t) ]_1 from { [x^i] } i=0..n-1

    libff::enter_block("computing [Lagrange_i(x)]_1");
    std::vector<G1> Lagrange_g1(
        pot.tau_powers_g1.begin(), pot.tau_powers_g1.begin() + n);
    assert(Lagrange_g1[0] == G1::one());
    assert(Lagrange_g1.size() == n);
    basic_radix2_iFFT(Lagrange_g1, omega_inv);
    libff::leave_block("computing [Lagrange_i(x)]_1");

    libff::enter_block("computing [Lagrange_i(x)]_2");
    std::vector<G2> Lagrange_g2(
        pot.tau_powers_g2.begin(), pot.tau_powers_g2.begin() + n);
    assert(Lagrange_g2[0] == G2::one());
    assert(Lagrange_g2.size() == n);
    basic_radix2_iFFT(Lagrange_g2, omega_inv);
    libff::leave_block("computing [Lagrange_i(x)]_2");

    libff::enter_block("computing [alpha . Lagrange_i(x)]_1");
    std::vector<G1> alpha_lagrange_g1(
        pot.alpha_tau_powers_g1.begin(), pot.alpha_tau_powers_g1.begin() + n);
    assert(alpha_lagrange_g1.size() == n);
    basic_radix2_iFFT(alpha_lagrange_g1, omega_inv);
    libff::leave_block("computing [alpha . Lagrange_i(x)]_1");

    libff::enter_block("computing [beta . Lagrange_i(x)]_1");
    std::vector<G1> beta_lagrange_g1(
        pot.beta_tau_powers_g1.begin(), pot.beta_tau_powers_g1.begin() + n);
    assert(beta_lagrange_g1.size() == n);
    basic_radix2_iFFT(beta_lagrange_g1, omega_inv);
    libff::leave_block("computing [beta . Lagrange_i(x)]_1");

    libff::enter_block("computing A_i, B_i, C_i, ABC_i at x");
    libff::G1_vector<ppT> As_g1(num_variables + 1);
    libff::G1_vector<ppT> Bs_g1(num_variables + 1);
    libff::G2_vector<ppT> Bs_g2(num_variables + 1);
    libff::G1_vector<ppT> Cs_g1(num_variables + 1);
    libff::G1_vector<ppT> ABCs_g1(num_variables + 1);
    for (size_t j = 0; j < num_variables + 1; ++j) {
        G1 ABC_j_at_x = G1::zero();

        {
            G1 A_j_at_x = G1::zero();
            const std::map<size_t, Fr> &A_j_lagrange =
                qap.A_in_Lagrange_basis[j];
            for (const auto &entry : A_j_lagrange) {
                A_j_at_x = A_j_at_x + (entry.second * Lagrange_g1[entry.first]);
                ABC_j_at_x =
                    ABC_j_at_x + (entry.second * beta_lagrange_g1[entry.first]);
            }

            As_g1[j] = A_j_at_x;
        }

        {
            G1 B_j_at_x_g1 = G1::zero();
            G2 B_j_at_x_g2 = G2::zero();

            const std::map<size_t, Fr> &B_j_lagrange =
                qap.B_in_Lagrange_basis[j];
            for (const auto &entry : B_j_lagrange) {
                B_j_at_x_g1 =
                    B_j_at_x_g1 + (entry.second * Lagrange_g1[entry.first]);
                B_j_at_x_g2 =
                    B_j_at_x_g2 + (entry.second * Lagrange_g2[entry.first]);
                ABC_j_at_x = ABC_j_at_x +
                             (entry.second * alpha_lagrange_g1[entry.first]);
            }

            Bs_g1[j] = B_j_at_x_g1;
            Bs_g2[j] = B_j_at_x_g2;
        }

        {
            G1 C_j_at_x = G1::zero();
            const std::map<size_t, Fr> &C_j_lagrange =
                qap.C_in_Lagrange_basis[j];
            for (const auto &entry : C_j_lagrange) {
                C_j_at_x = C_j_at_x + entry.second * Lagrange_g1[entry.first];
            }

            Cs_g1[j] = C_j_at_x;
            ABC_j_at_x = ABC_j_at_x + C_j_at_x;
        }

        ABCs_g1[j] = ABC_j_at_x;
    }
    libff::leave_block("computing A_i, B_i, C_i, ABC_i at x");

    // For each $i$ in turn, compute the exp table for $[x^i]$ and
    // apply it everywhere, before moving on to the next power.
    libff::enter_block("computing [t(x) . x^i]_1");
    libff::G1_vector<ppT> t_x_pow_i(n - 1, G1::zero());
    for (size_t i = 0; i < 2 * n - 1; ++i) {
        std::cout << "\r(" << std::to_string(i) << "/"
                  << std::to_string(2 * n - 1) << ")";

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
        const size_t begin_T = (size_t)std::max<ssize_t>((ssize_t)i - n, 0);
        const size_t end_T = std::min<size_t>(n - 1, i + 1);

        // Compute parameters for window table.
        // Number of coefficients = end_t - begin_T.
        const size_t num_scalars = end_T - begin_T;
        const size_t window_size = libff::get_exp_window_size<G1>(num_scalars);
        libff::window_table<libff::G1<ppT>> tau_pow_i_table =
            libff::get_window_table(
                scalar_size, window_size, pot.tau_powers_g1[i]);

        for (size_t j = begin_T; j < end_T; ++j) {
            const G1 T_j_contrib = windowed_exp(
                scalar_size,
                window_size,
                tau_pow_i_table,
                t_coefficients[i - j]);
            t_x_pow_i[j] = t_x_pow_i[j] + T_j_contrib;
        }
    }
    libff::enter_block("computing [t(x) . x^i]_1");

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
