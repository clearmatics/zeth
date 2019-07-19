#include "crs.hpp"
#include "multi_exp.hpp"
#include "evaluation_from_lagrange.hpp"
#include <libff/algebra/scalar_multiplication/multiexp.hpp>

using namespace libsnark;

using ppT = libff::default_ec_pp;
using FieldT = libff::Fr<ppT>;
using Fr = libff::Fr<ppT>;
using G1 = libff::G1<ppT>;


///
template<typename ppT>
r1cs_gg_ppzksnark_crs1<ppT>::r1cs_gg_ppzksnark_crs1(
        libff::G1_vector<ppT> &&tau_powers_g1,
        libff::G1_vector<ppT> &&tau_powers_g2,
        libff::G1_vector<ppT> &&alpha_tau_powers_g1,
        libff::G1_vector<ppT> &&beta_tau_g1,
        libff::G1<ppT> &&delta_g1,
        libff::G2<ppT> &&delta_g2)
        : tau_powers_g1(std::move(tau_powers_g1))
        , tau_powers_g2(std::move(tau_powers_g2))
        , alpha_tau_powers_g1(std::move(alpha_tau_powers_g1))
        , beta_tau_powers_g1(std::move(beta_tau_g1))
        , delta_g1(std::move(delta_g1))
        , delta_g2(std::move(delta_g2))
    {
    }


///
template<typename ppT>
r1cs_gg_ppzksnark_crs2<ppT>::r1cs_gg_ppzksnark_crs2(
    libff::G1_vector<ppT> &&T_tau_powers,
    libff::G1_vector<ppT> &&ABC_g1)
    : T_tau_powers(std::move(T_tau_powers))
    , ABC_g1(std::move(ABC_g1))
{
}



r1cs_gg_ppzksnark_crs2<ppT>
r1cs_gg_ppzksnark_generator_phase2(
    const r1cs_gg_ppzksnark_crs1<ppT> &crs1,
    const r1cs_constraint_system<Fr> &cs)
{
    // QAP

    qap_instance<FieldT> qap = r1cs_to_qap_instance_map(cs);
    libfqfft::evaluation_domain<FieldT> &domain = *qap.domain;

    const size_t order_L = qap.domain->m;
    const size_t num_variables = qap.num_variables();
    const size_t ABC_degree = qap.degree();

    assert(crs1.tau_powers_g1.size() > order_L + order_L + 2);
    assert(ABC_degree == order_L);
    assert(ABC_degree <= crs1.tau_powers_g1.size());

    // Compute [ t(x) . x^i ]_1

    std::vector<Fr> t_coefficients(order_L + 1, Fr::zero());
    qap.domain->add_poly_Z(Fr::one(), t_coefficients);
    libff::G1_vector<ppT> t_x_pow_i;
    for (size_t i = 0 ; i < order_L + 1 ; ++i)
    {
        // Use { [x^i] , ... , [x^(i+order_L+1)] }
        t_x_pow_i.push_back(
            multi_exp<ppT>(
                crs1.tau_powers_g1.begin() + i,
                crs1.tau_powers_g1.begin() + i + order_L + 1,
                t_coefficients.begin(),
                t_coefficients.end())
        );
    }

    // Compute [ beta.A_i(x) + alpha.B_i(x) + C_i(x) ]_1
    //
    // For each i, get the Lagrange factors of A_i, B_i, C_i.  For
    // each j, if A, B or C has a non-zero factor, grab the Lagrange
    // coefficients, evaluate at [t]_1, multiply by the factor and
    // accumulate.

    libff::G1_vector<ppT> ABC_i_g1(num_variables);

    evaluation_from_lagrange<ppT> tau_eval(crs1.tau_powers_g1, domain);
    evaluation_from_lagrange<ppT> alpha_tau_eval(crs1.alpha_tau_powers_g1, domain);
    evaluation_from_lagrange<ppT> beta_tau_eval(crs1.beta_tau_powers_g1, domain);

    for (size_t i = 0 ; i < num_variables ; ++i)
    {
        // Compute [beta.A_i(x)], [alpha.B_i(x)] . [C_i(x)]

        const std::map<size_t, Fr> &A_i_in_lagrange = qap.A_in_Lagrange_basis[i];
        const std::map<size_t, Fr> &B_i_in_lagrange = qap.A_in_Lagrange_basis[i];
        const std::map<size_t, Fr> &C_i_in_lagrange = qap.A_in_Lagrange_basis[i];

        G1 beta_A_at_t = beta_tau_eval.evaluate_from_langrange_factors(
            A_i_in_lagrange);
        G1 alpha_B_at_t = alpha_tau_eval.evaluate_from_langrange_factors(
            B_i_in_lagrange);
        G1 C_at_t = tau_eval.evaluate_from_langrange_factors(
            C_i_in_lagrange);

        ABC_i_g1.push_back(beta_A_at_t + alpha_B_at_t + C_at_t);
    }

    return r1cs_gg_ppzksnark_crs2<ppT>(
        std::move(t_x_pow_i),
        std::move(ABC_i_g1));
}


r1cs_gg_ppzksnark_keypair<ppT>
r1cs_gg_ppzksnark_generator_phase3(
    const r1cs_gg_ppzksnark_crs1<ppT> &crs1,
    const r1cs_gg_ppzksnark_crs2<ppT> &crs2)
{
    // TODO:

    (void)crs1;
    (void)crs2;
    return r1cs_gg_ppzksnark_keypair<ppT>();
}
