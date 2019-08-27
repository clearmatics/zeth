#ifndef __ZETH_SNARKS_GROTH_POWERSOFTAU_UTILS_HPP__
#define __ZETH_SNARKS_GROTH_POWERSOFTAU_UTILS_HPP__

#include "include_libsnark.hpp"

#include <istream>

namespace libzeth
{

using ppT = libff::default_ec_pp;

/// Output from the first phase of the MPC (powersoftau).  The
/// structure matches that data exactly (no indication of degree,
/// etc), so that it can be loaded directly.
class srs_powersoftau
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

    srs_powersoftau(
        libff::G1_vector<ppT> &&tau_powers_g1,
        libff::G2_vector<ppT> &&tau_powers_g2,
        libff::G1_vector<ppT> &&alpha_tau_powers_g1,
        libff::G1_vector<ppT> &&beta_tau_g1,
        const libff::G2<ppT> &beta_g2);
};

/// Given some secrets, compute a dummy set of powersoftau, for
/// circuits with polynomials A, B, C order-bound by `n` .
srs_powersoftau dummy_powersoftau_from_secrets(
    const libff::Fr<ppT> &tau,
    const libff::Fr<ppT> &alpha,
    const libff::Fr<ppT> &beta,
    size_t n);

/// Same as dummy_powersoftau_from_secrets(), where the secrets are not
/// of interest.
srs_powersoftau dummy_powersoftau(size_t n);

/// Implements the SameRatio described in "Scalable Multi-party
/// Computation for zk-SNARK Parameters in the Random Beacon Model"
/// http://eprint.iacr.org/2017/1050
template<typename ppT>
bool same_ratio(
    const libff::G1<ppT> &a1,
    const libff::G1<ppT> &b1,
    const libff::G2<ppT> &a2,
    const libff::G2<ppT> &b2);

/// Verify that the pot data is well formed.
bool powersoftau_validate(const srs_powersoftau &pot, const size_t n);

} // namespace libzeth

#endif // __ZETH_SNARKS_GROTH_POWERSOFTAU_UTILS_HPP__
