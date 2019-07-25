
// #pragma GCC diagnostic push
// #pragma GCC diagnostic ignored "-Wdelete-non-virtual-dtor"

// # include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
// # include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"
// # include "libsnark/gadgetlib1/pb_variable.hpp"

// #pragma GCC diagnostic pop

#include "include_libsnark.hpp"
#include "snarks/groth16/multi_exp.hpp"
#include <gtest/gtest.h>

using ppT = libff::default_ec_pp;
using FieldT = libff::Fr<ppT>;
using namespace libsnark;

namespace
{

TEST(MultiExpTests, MultiExpG1)
{
    // {a0, a1, a2} \in F
    // [b0, b1, b2} \in F
    // {A0, A1, A2} = {g^a0, g^a1, g^a2} \in G2
    // poly eval ([b's], [A's]) == g^(a0.b0 + a1.b1 + a2.b1)

    libff::Fr_vector<ppT> as = {
        FieldT::random_element(),
        FieldT::random_element(),
        FieldT::random_element(),
    };

    libff::Fr_vector<ppT> bs = {
        FieldT::random_element(),
        FieldT::random_element(),
        FieldT::random_element(),
    };

    libff::G1<ppT> g = libff::G1<ppT>::random_element();

    libff::G1_vector<ppT> gs = {
        as[0] * g,
        as[1] * g,
        as[2] * g,
    };

    libff::G1<ppT> me1 = multi_exp<ppT>(gs, bs);
    libff::G1<ppT> me2 = bs[0] * gs[0] + bs[1] * gs[1] + bs[2] * gs[2];

    ASSERT_EQ(me2, me1);
}

} // namespace


int main(int argc, char **argv)
{
    // !!! WARNING: Do not forget to do this once for all tests !!!
    ppT::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
