#ifndef __ZETH_CRS_HPP__
#define __ZETH_CRS_HPP__

#include "include_libsnark.hpp"
#include <vector>

/// Output from the first phase of the MPC (powersoftau).
template<typename ppT>
class r1cs_gg_ppzksnark_crs1
{
public:

    /// { [ x^i ]_1 }  i = 0 .. 2n-2
    const libff::G1_vector<ppT> tau_powers_g1;

    /// { [ x^i ]_2 }  i = 0 .. n-1
    const libff::G2_vector<ppT> tau_powers_g2;

    /// { [ alpha . x^i ]_1 }  i = 0 .. n-1
    const libff::G1_vector<ppT> alpha_tau_powers_g1;

    /// { [ beta . x^i ]_1 }  i = 0 .. n-1
    const libff::G1_vector<ppT> beta_tau_powers_g1;

    /// [ beta ]_2
    const libff::G2<ppT> beta_g2;

    r1cs_gg_ppzksnark_crs1(
        libff::G1_vector<ppT> &&tau_powers_g1,
        libff::G2_vector<ppT> &&tau_powers_g2,
        libff::G1_vector<ppT> &&alpha_tau_powers_g1,
        libff::G1_vector<ppT> &&beta_tau_g1,
        const libff::G2<ppT> &beta_g2);
};


/// Output from the second layer of the CRS computation.  Created as
/// linear combinations of elements in r1cs_gg_ppzksnark_crs1, based
/// on a specific circuit.
template<typename ppT>
class r1cs_gg_ppzksnark_crs2
{
public:

    // TOOD: Some of these can be sparse

    /// { [ t(x) . x^i ]_1 }  i = 0 .. n-1
    libff::G1_vector<ppT> T_tau_powers_g1;

    /// { [ A_i(x) ]_1 }  i = 0 .. m
    libff::G1_vector<ppT> A_g1;

    /// { [ B_i(x) ]_1 }  i = 0 .. m
    libff::G1_vector<ppT> B_g1;

    /// { [ B_i(x) ]_2 }  i = 0 .. m
    libff::G2_vector<ppT> B_g2;

    /// { [ beta . A_i(x) + alpha . B_i(x) + C_i(x) ]_1 }  i = l+1 ... m
    libff::G1_vector<ppT> ABC_g1;

    r1cs_gg_ppzksnark_crs2(
        libff::G1_vector<ppT> &&T_tau_powers_g1,
        libff::G1_vector<ppT> &&A_g1,
        libff::G1_vector<ppT> &&B_g1,
        libff::G2_vector<ppT> &&B_g2,
        libff::G1_vector<ppT> &&ABC_g1);
};


/// Confirm that the ratio a1:b1 in G1 equals a2:b2 in G2 by checking:
///   e( a1, b2 ) == e( b1, a2 )
template <typename ppT>
bool same_ratio(
    const libff::G1<ppT> &a1,
    const libff::G1<ppT> &b1,
    const libff::G2<ppT> &a2,
    const libff::G2<ppT> &b2);


/// Verify that a CRS1 structure is well-formed.
template <typename ppT>
bool r1cs_gg_ppzksnark_crs1_validate(
    const r1cs_gg_ppzksnark_crs1<ppT> &crs1,
    const size_t n);

/// Given a circuit and a crs1, perform the correct linear
/// combinations of elements in crs1 to get the extra from the 2nd
/// layer of the CRS MPC.
template <typename ppT>
r1cs_gg_ppzksnark_crs2<ppT>
r1cs_gg_ppzksnark_generator_phase2(
    const r1cs_gg_ppzksnark_crs1<ppT> &crs1,
    const libsnark::qap_instance<libff::Fr<ppT>> &qap);

/// Given the output from the first two layers of the MPC, perform the
/// 3rd layer computation using just local randomness.  This is not a
/// substitute for the full MPC with an auditable log of contributions,
/// but is useful for testing.
template <typename ppT>
libsnark::r1cs_gg_ppzksnark_keypair<ppT>
r1cs_gg_ppzksnark_generator_dummy_phase3(
    const r1cs_gg_ppzksnark_crs1<ppT> &&crs1,
    const r1cs_gg_ppzksnark_crs2<ppT> &&crs2,
    const libff::Fr<ppT> &delta,
    libsnark::r1cs_constraint_system<libff::Fr<ppT>> &&cs,
    const libsnark::qap_instance<libff::Fr<ppT>> &qap);

//
#include "crs.tcc"

#endif // __ZETH_CRS_HPP__
