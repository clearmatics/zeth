#ifndef __ZETH_SNARKS_GROTH16_MPC_UTILS_HPP__
#define __ZETH_SNARKS_GROTH16_MPC_UTILS_HPP__

#include "include_libsnark.hpp"

#include <vector>

// Structures and utility functions related to CRS generation via an
// MPC. Following [BoweGM17], the circuit $C$ generating the SRS is
// considered to be made up of 3 layers: $C = C_1 L_1 C_2$.  The
// output from $C_1$ is exactly the powersoftau data. $L_1$
// represents the linear combination based on a specific QAP, and
// $C_2$ is the output from Phase2 of the MPC.
//
// References:
//
// \[BoweGM17]
//  "Scalable Multi-party Computation for zk-SNARK Parameters in the Random
//  Beacon Model"
//  Sean Bowe and Ariel Gabizon and Ian Miers,
//  IACR Cryptology ePrint Archive 2017,
//  <http://eprint.iacr.org/2017/1050>

namespace libzeth
{

template<typename ppT> class srs_powersoftau;
template<typename ppT> class srs_lagrange_evaluations;

/// Output from linear combination $L_1$ - the linear combination of
/// elements in powersoftau, based on a specific circuit.
template<typename ppT> class srs_mpc_layer_L1
{
public:
    /// { [ t(x) . x^i ]_1 }  i = 0 .. n-2
    libff::G1_vector<ppT> T_tau_powers_g1;

    /// { [ A_i(x) ]_1 }  i = 0 .. m
    libff::G1_vector<ppT> A_g1;

    /// { [ B_i(x) ]_1 }  i = 0 .. m
    libff::G1_vector<ppT> B_g1;

    /// { [ B_i(x) ]_2 }  i = 0 .. m
    libff::G2_vector<ppT> B_g2;

    /// { [ beta . A_i(x) + alpha . B_i(x) + C_i(x) ]_1 }  i = l+1 ... m
    libff::G1_vector<ppT> ABC_g1;

    srs_mpc_layer_L1(
        libff::G1_vector<ppT> &&T_tau_powers_g1,
        libff::G1_vector<ppT> &&A_g1,
        libff::G1_vector<ppT> &&B_g1,
        libff::G2_vector<ppT> &&B_g2,
        libff::G1_vector<ppT> &&ABC_g1);

    size_t degree() const;

    bool is_well_formed() const;
    void write(std::ostream &out) const;
    static srs_mpc_layer_L1 read(std::istream &in);
};

/// Given a circuit and a powersoftau with pre-computed lagrange
/// polynomials, perform the correct linear combination for the CRS MPC.
template<typename ppT>
srs_mpc_layer_L1<ppT> mpc_compute_linearcombination(
    const srs_powersoftau<ppT> &pot,
    const srs_lagrange_evaluations<ppT> &lagrange,
    const libsnark::qap_instance<libff::Fr<ppT>> &qap);

} // namespace libzeth

#include "snarks/groth16/mpc_utils.tcc"

#endif // __ZETH_SNARKS_GROTH16_MPC_UTILS_HPP__
