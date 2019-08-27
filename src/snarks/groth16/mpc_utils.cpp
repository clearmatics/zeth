#include "mpc_utils.hpp"

using namespace libsnark;

namespace libzeth
{

using ppT = libff::default_ec_pp;
using Fr = libff::Fr<ppT>;
using G1 = libff::G1<ppT>;
using G2 = libff::G2<ppT>;

// -----------------------------------------------------------------------------
// srs_mpc_layer_L1
// -----------------------------------------------------------------------------

srs_mpc_layer_L1::srs_mpc_layer_L1(
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

} // namespace libzeth
