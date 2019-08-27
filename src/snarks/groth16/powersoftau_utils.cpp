
#include "powersoftau_utils.hpp"

namespace libzeth
{

using ppT = libff::default_ec_pp;
using Fr = libff::Fr<ppT>;
using G1 = libff::G1<ppT>;
using G2 = libff::G2<ppT>;

// -----------------------------------------------------------------------------
// powersoftau
// -----------------------------------------------------------------------------

srs_powersoftau::srs_powersoftau(
    libff::G1_vector<ppT> &&tau_powers_g1,
    libff::G2_vector<ppT> &&tau_powers_g2,
    libff::G1_vector<ppT> &&alpha_tau_powers_g1,
    libff::G1_vector<ppT> &&beta_tau_powers_g1,
    const libff::G2<ppT> &beta_g2)
    : tau_powers_g1(std::move(tau_powers_g1))
    , tau_powers_g2(std::move(tau_powers_g2))
    , alpha_tau_powers_g1(std::move(alpha_tau_powers_g1))
    , beta_tau_powers_g1(std::move(beta_tau_powers_g1))
    , beta_g2(beta_g2)
{
}

} // namespace libzeth
