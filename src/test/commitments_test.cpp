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


TEST(TestCOMMs, TestCOMMInnerKGadget) {
    ppT::init_public_params();
    libsnark::protoboard<FieldT> pb;

    libsnark::pb_variable<FieldT> a_pk;
    libsnark::pb_variable<FieldT> rho;

    a_pk.allocate(pb, "a_pk");
    pb.val(a_pk) = FieldT("19542864813983728673570354644600990996826782795988858036533765820146220345183");

    rho.allocate(pb, "rho");
    pb.val(rho) = FieldT("6707574354230822882728245456150029507327662563672602557855634841940058902338");

    COMM_gadget<FieldT> comm_inner_test_gadget(pb, a_pk, rho, "COMM_inner_test_gadget");

    comm_inner_test_gadget.generate_r1cs_constraints();
    comm_inner_test_gadget.generate_r1cs_witness();

    FieldT expected_out = FieldT("15473123422536687185135647414451543863834058946824121428596687730677885598755");

    ASSERT_TRUE(expected_out == pb.val(comm_inner_test_gadget.result()));

};

TEST(TestCOMMs, TestCOMMOuterKGadget) {
  ppT::init_public_params();
  libsnark::protoboard<FieldT> pb;

  libsnark::pb_variable<FieldT> r0;
  libsnark::pb_variable<FieldT> r1;
  libsnark::pb_variable<FieldT> masked;

  libsnark::pb_variable<FieldT> inner_comm;

  masked.allocate(pb, "masked");

  r0.allocate(pb, "r trap");
  pb.val(r0) = FieldT("2998811441792601712851203975027567775313089568844489772255494278089442886910");

  r1.allocate(pb, "r mask");
  pb.val(r1) = FieldT("16667265961160010607297656097879823469399865294150712476086065681397164544011");

  inner_comm.allocate(pb, "inner_comm");
  pb.val(inner_comm) = FieldT("15473123422536687185135647414451543863834058946824121428596687730677885598755");

  COMM_outer_k_gadget<FieldT> comm_outer_test_gadget(pb, r0, r1, masked, inner_comm, "COMM_outer_test_gadget");

  comm_outer_test_gadget.generate_r1cs_constraints();
  comm_outer_test_gadget.generate_r1cs_witness();

  FieldT expected_out = FieldT("17755525730227548761740123721131996788472041905859814266612454742596539275973");

  ASSERT_TRUE(expected_out == pb.val(comm_outer_test_gadget.result()));
};

TEST(TestCOMMs, TestCOMMCMGadget) {
  ppT::init_public_params();
  libsnark::protoboard<FieldT> pb;

  libsnark::pb_variable<FieldT> outer_comm;
  libsnark::pb_variable<FieldT> v;

  outer_comm.allocate(pb, "outer_comm");
  pb.val(outer_comm) = FieldT("17755525730227548761740123721131996788472041905859814266612454742596539275973");

  v.allocate(pb, "v");
  pb.val(v) = FieldT("100");

  COMM_gadget<FieldT> comm_test_gadget(pb, outer_comm, v, "COMM_test_gadget");

  comm_test_gadget.generate_r1cs_constraints();
  comm_test_gadget.generate_r1cs_witness();

  FieldT expected_out = FieldT("21143498282498593887430678658261061148773654198094463922036029572048065734021");
  std::cout << "*******" << std::endl;

  ASSERT_TRUE(expected_out == pb.val(comm_test_gadget.result()));
};

} // namespace

int main(int argc, char **argv) {
    ppT::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
