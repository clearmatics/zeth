#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>

// Get the gadget to test
#include "circuits/commitments/commitments.hpp"

using namespace libzeth;
using namespace libsnark;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT; // Should be alt_bn128 in the CMakeLists.txt

namespace {

TEST(TestCOMMs, TestCMGadget) {
  ppT::init_public_params();
  protoboard<FieldT> pb;


  libsnark::pb_variable<FieldT> a_pk;
  libsnark::pb_variable<FieldT> rho;
  libsnark::pb_variable<FieldT> r0;
  libsnark::pb_variable<FieldT> v;

  a_pk.allocate(pb, "a_pk");
  pb.val(a_pk) = FieldT("19542864813983728673570354644600990996826782795988858036533765820146220345183");

  rho.allocate(pb, "rho");
  pb.val(rho) = FieldT("6707574354230822882728245456150029507327662563672602557855634841940058902338");

  r0.allocate(pb, "r trap");
  pb.val(r0) = FieldT("2998811441792601712851203975027567775313089568844489772255494278089442886910");

  v.allocate(pb, "v");
  pb.val(v) = FieldT("100");

  cm_gadget<FieldT> cm_gadget(pb, a_pk, rho, r0,  v, "cm_test_gadget");

  cm_gadget.generate_r1cs_constraints();
  cm_gadget.generate_r1cs_witness();

  FieldT expected_out = FieldT("12358985269798453918570078816455146271632486474291071895597592689261027810088");

  ASSERT_TRUE(expected_out == pb.val(cm_gadget.result()));
};


} // namespace

int main(int argc, char **argv) {
    ppT::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
