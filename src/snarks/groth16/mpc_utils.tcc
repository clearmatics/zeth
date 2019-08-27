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

template<typename ppT> size_t srs_mpc_layer_L1<ppT>::degree() const
{
    return T_tau_powers_g1.size() + 1;
}

template<typename ppT>
void srs_mpc_layer_L1<ppT>::write(std::ostream &out) const
{
    using G1 = libff::G1<ppT>;
    using G2 = libff::G2<ppT>;

    // Write the sizes first, then stream out the values.
    const size_t num_T_tau_powers = T_tau_powers_g1.size();
    const size_t num_polynomials = A_g1.size();
    out.write((const char *)&num_T_tau_powers, sizeof(num_T_tau_powers));
    out.write((const char *)&num_polynomials, sizeof(num_polynomials));

    for (const G1 &v : T_tau_powers_g1) {
        out << v;
    }

    for (const G1 &v : A_g1) {
        out << v;
    }

    for (const G1 &v : B_g1) {
        out << v;
    }

    for (const G2 &v : B_g2) {
        out << v;
    }

    for (const G1 &v : ABC_g1) {
        out << v;
    }
}

template<typename ppT>
srs_mpc_layer_L1<ppT> srs_mpc_layer_L1<ppT>::read(std::istream &in)
{
    using G1 = libff::G1<ppT>;
    using G2 = libff::G2<ppT>;

    size_t num_T_tau_powers;
    size_t num_polynomials;

    in.read((char *)&num_T_tau_powers, sizeof(num_T_tau_powers));
    in.read((char *)&num_polynomials, sizeof(num_polynomials));

    libff::G1_vector<ppT> T_tau_powers_g1(num_T_tau_powers);
    libff::G1_vector<ppT> A_g1(num_polynomials);
    libff::G1_vector<ppT> B_g1(num_polynomials);
    libff::G2_vector<ppT> B_g2(num_polynomials);
    libff::G1_vector<ppT> ABC_g1(num_polynomials);

    for (G1 &v : T_tau_powers_g1) {
        in >> v;
    }

    for (G1 &v : A_g1) {
        in >> v;
    }

    for (G1 &v : B_g1) {
        in >> v;
    }

    for (G2 &v : B_g2) {
        in >> v;
    }

    for (G1 &v : ABC_g1) {
        in >> v;
    }

    return srs_mpc_layer_L1<ppT>(
        std::move(T_tau_powers_g1),
        std::move(A_g1),
        std::move(B_g1),
        std::move(B_g2),
        std::move(ABC_g1));
}

template<typename ppT>
srs_mpc_layer_L1<ppT> mpc_compute_linearcombination(
    const srs_powersoftau<ppT> &pot,
    const srs_lagrange_evaluations<ppT> &lagrange,
    const libsnark::qap_instance<libff::Fr<ppT>> &qap)
{
    using Fr = libff::Fr<ppT>;
    using G1 = libff::G1<ppT>;
    using G2 = libff::G2<ppT>;
    libff::enter_block("Call to mpc_compute_linearcombination");

    // n = number of constraints in r1cs, or equivalently, n = deg(t(x))
    // t(x) being the target polynomial of the QAP
    // Note: In the code-base the target polynomial is also denoted Z
    // as refered to as "the vanishing polynomial", and t is also used
    // to represent the query point (aka "tau").
    const size_t n = qap.degree();
    const size_t num_variables = qap.num_variables();

    if (n != 1ull << libff::log2(n)) {
        throw std::invalid_argument("non-pow-2 domain");
    }
    if (n != lagrange.degree) {
        throw std::invalid_argument(
            "domain size differs from Lagrange evaluation");
    }

    libff::print_indent();
    printf("n=%zu\n", n);

    // The QAP polynomials A, B, C are of degree (n-1) as we know they
    // are created by interpolation of an r1cs of n constraints.
    // As a consequence, the polynomial (A.B - C) is of degree 2n-2,
    // while the target polynomial t is of degree n.
    // Thus, we need to have access (in the SRS) to powers up to 2n-2.
    // To represent such polynomials we need {x^i} for in {0, ... n-2}
    // hence we check below that we have at least n-1 elements
    // in the set of powers of tau
    assert(pot.tau_powers_g1.size() >= 2 * n - 1);

    // Domain uses n-roots of unity, so
    //      t(x)       = x^n - 1
    //  =>  t(x) . x^i = x^(n+i) - x^i
    libff::G1_vector<ppT> t_x_pow_i(n - 1, G1::zero());
    libff::enter_block("computing [t(x) . x^i]_1");
    for (size_t i = 0; i < n - 1; ++i) {
        t_x_pow_i[i] = pot.tau_powers_g1[n + i] - pot.tau_powers_g1[i];
    }
    libff::leave_block("computing [t(x) . x^i]_1");

    libff::enter_block("computing A_i, B_i, C_i, ABC_i at x");
    libff::G1_vector<ppT> As_g1(num_variables + 1);
    libff::G1_vector<ppT> Bs_g1(num_variables + 1);
    libff::G2_vector<ppT> Bs_g2(num_variables + 1);
    libff::G1_vector<ppT> Cs_g1(num_variables + 1);
    libff::G1_vector<ppT> ABCs_g1(num_variables + 1);
#ifdef MULTICORE
#pragma omp parallel for
#endif
    for (size_t j = 0; j < num_variables + 1; ++j) {
        G1 ABC_j_at_x = G1::zero();

        {
            G1 A_j_at_x = G1::zero();
            const std::map<size_t, Fr> &A_j_lagrange =
                qap.A_in_Lagrange_basis[j];
            for (const auto &entry : A_j_lagrange) {
                A_j_at_x = A_j_at_x +
                           (entry.second * lagrange.lagrange_g1[entry.first]);
                ABC_j_at_x =
                    ABC_j_at_x +
                    (entry.second * lagrange.beta_lagrange_g1[entry.first]);
            }

            As_g1[j] = A_j_at_x;
        }

        {
            G1 B_j_at_x_g1 = G1::zero();
            G2 B_j_at_x_g2 = G2::zero();

            const std::map<size_t, Fr> &B_j_lagrange =
                qap.B_in_Lagrange_basis[j];
            for (const auto &entry : B_j_lagrange) {
                B_j_at_x_g1 = B_j_at_x_g1 + (entry.second *
                                             lagrange.lagrange_g1[entry.first]);
                B_j_at_x_g2 = B_j_at_x_g2 + (entry.second *
                                             lagrange.lagrange_g2[entry.first]);
                ABC_j_at_x =
                    ABC_j_at_x +
                    (entry.second * lagrange.alpha_lagrange_g1[entry.first]);
            }

            Bs_g1[j] = B_j_at_x_g1;
            Bs_g2[j] = B_j_at_x_g2;
        }

        {
            G1 C_j_at_x = G1::zero();
            const std::map<size_t, Fr> &C_j_lagrange =
                qap.C_in_Lagrange_basis[j];
            for (const auto &entry : C_j_lagrange) {
                C_j_at_x =
                    C_j_at_x + entry.second * lagrange.lagrange_g1[entry.first];
            }

            Cs_g1[j] = C_j_at_x;
            ABC_j_at_x = ABC_j_at_x + C_j_at_x;
        }

        ABCs_g1[j] = ABC_j_at_x;
    }
    libff::leave_block("computing A_i, B_i, C_i, ABC_i at x");

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
    srs_powersoftau<ppT> &&pot,
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
