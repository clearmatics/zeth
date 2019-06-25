#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Header to use the sha256_ethereum gadget
#include "circuits/sha256/sha256_ethereum.hpp"

// Access the `from_bits` function and other utils
#include "circuits/circuits-util.hpp"
#include "util.hpp"

// Get the gadget to test
#include "circuits/commitments/commitments.hpp"

using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT; // Should be alt_bn128 in the CMakeLists.txt

namespace {

TEST(TestCOMMs, TestCMGadget) {
  ppT::init_public_params();
  libsnark::protoboard<FieldT> pb;


  libsnark::pb_variable<FieldT> a_pk;
  libsnark::pb_variable<FieldT> rho;
  libsnark::pb_variable<FieldT> r0;
  libsnark::pb_variable<FieldT> r1;
  libsnark::pb_variable<FieldT> v;

  a_pk.allocate(pb, "a_pk");
  pb.val(a_pk) = FieldT("19542864813983728673570354644600990996826782795988858036533765820146220345183");

  rho.allocate(pb, "rho");
  pb.val(rho) = FieldT("6707574354230822882728245456150029507327662563672602557855634841940058902338");

  //pb.val(inner_comm) = FieldT("15473123422536687185135647414451543863834058946824121428596687730677885598755");

  //pb.val(outer_comm) = FieldT("17755525730227548761740123721131996788472041905859814266612454742596539275973");

  r0.allocate(pb, "r trap");
  pb.val(r0) = FieldT("2998811441792601712851203975027567775313089568844489772255494278089442886910");

  r1.allocate(pb, "r mask");
  pb.val(r1) = FieldT("16667265961160010607297656097879823469399865294150712476086065681397164544011");

  v.allocate(pb, "v");
  pb.val(v) = FieldT("100");

  libsnark::pb_variable<FieldT> masked;
  masked.allocate(pb, "masked");

  libsnark::pb_variable<FieldT> k;
  masked.allocate(pb, "outer k");

  cm_gadget<FieldT> cm_gadget(pb, a_pk, rho, r0, r1,  v, "cm_test_gadget");

  cm_gadget.generate_r1cs_constraints();
  cm_gadget.generate_r1cs_witness();

  FieldT expected_out = FieldT("21143498282498593887430678658261061148773654198094463922036029572048065734021");
  std::cout << "*******" << std::endl;

  ASSERT_TRUE(expected_out == pb.val(cm_gadget.result()));
};


} // namespace

int main(int argc, char **argv) {
    ppT::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
