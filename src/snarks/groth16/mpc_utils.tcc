#ifndef __ZETH_SNARKS_GROTH16_MPC_UTILS_TCC__
#define __ZETH_SNARKS_GROTH16_MPC_UTILS_TCC__

#include "evaluator_from_lagrange.hpp"
#include "mpc_utils.hpp"
#include "multi_exp.hpp"

#include <libff/algebra/scalar_multiplication/multiexp.hpp>

namespace libzeth
{

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

    return srs_mpc_layer_L1<ppT>(
        std::move(t_x_pow_i),
        std::move(A_i_g1),
        std::move(B_i_g1),
        std::move(B_i_g2),
        std::move(ABC_i_g1));
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

    // { H_i } = { [ t(x) . x^i / delta ]_i } i = 0 .. m-1
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
    const size_t num_L_elements = num_variables - num_inputs;

    assert(num_orig_ABC == num_variables + 1);

    // { ([B_i]_2, [B_i]_1) } i = 0 .. num_orig_ABC
    std::vector<libsnark::knowledge_commitment<G2, G1>> B_i(num_orig_ABC);
    for (size_t i = 0; i < num_orig_ABC; ++i) {
        B_i[i] = libsnark::knowledge_commitment<G2, G1>(
            layer1.B_g2[i], layer1.B_g1[i]);
    }

    assert(B_i.size() == qap.num_variables() + 1);

    // { L_i } = [ { ABC_i / delta } ]_1, i = l+1 .. num_variables
    libff::G1_vector<ppT> L_g1(num_L_elements);
    for (size_t i = 0; i < num_L_elements; ++i) {
        L_g1[i] = delta_inverse * layer1.ABC_g1[i + num_inputs + 1];
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
