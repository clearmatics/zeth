#include "circuits/mimc/mimc_mp.hpp"

#include "gtest/gtest.h"
#include <libff/common/default_types/ec_pp.hpp>

using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;

namespace
{

TEST(TestMiMCMp, TestTrue)
{
    libsnark::protoboard<FieldT> pb;

    // Public input
    libsnark::pb_variable<FieldT> y;
    y.allocate(pb, "y");
    pb.set_input_sizes(1);
    pb.val(y) = FieldT("1568395149631190174933950911896067630329022481212975289"
                       "0706581988986633412003"); // sha3_256("mimc")

    // Private inputs
    libsnark::pb_variable<FieldT> x;
    x.allocate(pb, "x");
    pb.val(x) = FieldT("3703141493535563179657531719960160174296085208671919316"
                       "200479060314459804651");

    MiMC_mp_gadget<FieldT> mimc_mp_gadget(pb, x, y, "gadget");
    mimc_mp_gadget.generate_r1cs_witness();
    mimc_mp_gadget.generate_r1cs_constraints();

    FieldT expected_out = FieldT("167979224495559946840631042142333962005996937"
                                 "15764605878168345782964540311877");
    ASSERT_TRUE(expected_out == pb.val(mimc_mp_gadget.result()));
}

TEST(TestMiMCMp, TestFalse)
{
    libsnark::protoboard<FieldT> pb;

    // Public input
    libsnark::pb_variable<FieldT> y;
    y.allocate(pb, "y");
    pb.set_input_sizes(1);
    pb.val(y) = FieldT("8272473133185905403731511349671041314111289765433456653"
                       "2528783843265082629790");

    // Private inputs
    libsnark::pb_variable<FieldT> x;
    x.allocate(pb, "x");
    pb.val(x) = FieldT("3703141493535563179657531719960160174296085208671919316"
                       "200479060314459804651");

    MiMC_mp_gadget<FieldT> mimc_mp_gadget(pb, x, y, "gadget");
    mimc_mp_gadget.generate_r1cs_witness();
    mimc_mp_gadget.generate_r1cs_constraints();

    FieldT not_expected_out = FieldT("15683951496311901749339509118960676303290"
                                     "224812129752890706581988986633412003");
    ASSERT_FALSE(not_expected_out == pb.val(mimc_mp_gadget.result()));
}

} // namespace

int main(int argc, char **argv)
{
    ppT::init_public_params(); // /!\ WARNING: Do once for all tests. Do not
                               // forget to do this !!!!
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
