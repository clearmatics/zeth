#pragma once

#include "include_libsnark.hpp"
#include <vector>

///
template<typename ppT>
class r1cs_gg_ppzksnark_crs1
{
public:

    /// { [ x^i ]_1 }  i = 0 .. 2n-2
    const libff::G1_vector<ppT> tau_powers_g1;

    /// { [ x^i ]_2 }  i = 0 .. n-1
    const libff::G1_vector<ppT> tau_powers_g2;

    /// { [ alpha . x^i ]_1 }  i = 0 .. n-1
    const libff::G1_vector<ppT> alpha_tau_powers_g1;

    /// { [ beta . x^i ]_1 }  i = 0 .. n-1
    const libff::G1_vector<ppT> beta_tau_powers_g1;

    /// [ delta ]_1
    const libff::G1<ppT> delta_g1;

    /// [ delta ]_2
    const libff::G2<ppT> delta_g2;

    r1cs_gg_ppzksnark_crs1(
        libff::G1_vector<ppT> &&tau_powers_g1,
        libff::G1_vector<ppT> &&tau_powers_g2,
        libff::G1_vector<ppT> &&alpha_tau_powers_g1,
        libff::G1_vector<ppT> &&beta_tau_g1,
        libff::G1<ppT> &&delta_g1,
        libff::G2<ppT> &&delta_g2);
};

///
template<typename ppT>
class r1cs_gg_ppzksnark_crs2
{
public:

    /// { [ t(x) . x^i ]_1 }  i = 0 .. n-1
    libff::G1_vector<ppT> T_tau_powers;

    /// { [ beta . A_i(x) + alpha . B_i(x) + C_i(x) ]_1 }  i = l+1 ... m
    libsnark::accumulation_vector<libff::G1<ppT> > ABC_g1;

    r1cs_gg_ppzksnark_crs2(
        libff::G1_vector<ppT> &&T_tau_powers,
        libff::G1_vector<ppT> &&ABC_g1);
};

///
template <typename ppT>
r1cs_gg_ppzksnark_crs2<ppT>
r1cs_gg_ppzksnark_generator_phase2(
    const r1cs_gg_ppzksnark_crs1<ppT> &crs1,
    const libsnark::r1cs_constraint_system<libff::Fr<ppT>> &cs);

///
template <typename ppT>
libsnark::r1cs_gg_ppzksnark_keypair<ppT>
r1cs_gg_ppzksnark_generator_phase3(
    const r1cs_gg_ppzksnark_crs1<ppT> &crs1,
    const r1cs_gg_ppzksnark_crs2<ppT> &crs2,
    const libsnark::r1cs_constraint_system<libff::Fr<ppT>> &cs);

///
