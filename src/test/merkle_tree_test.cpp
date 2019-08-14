#include "gtest/gtest.h"
#include <libff/common/default_types/ec_pp.hpp>
#include "circuits/merkle_tree/merkle_path_selector.hpp"
#include "circuits/merkle_tree/merkle_path_authenticator.hpp"
#include "circuits/mimc/mimc_mp.hpp"

using namespace libzeth;

// Instantiation of the templates for the tests
typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;
typedef MiMC_mp_gadget<FieldT> HashTreeT;

namespace {

bool test_merkle_path_selector(int is_right) {
  libsnark::protoboard<FieldT> pb;

  FieldT value_A = FieldT("149674538925118052205057075966660054952481571156186698930522557832224430770");
  FieldT value_B = FieldT("9670701465464311903249220692483401938888498641874948577387207195814981706974");

  is_right = is_right ? 1 : 0;

  libsnark::pb_variable<FieldT> var_A;
  var_A.allocate(pb, "var_A");

  pb.val(var_A) = value_A;

  libsnark::pb_variable<FieldT> var_B;
  var_B.allocate(pb, "var_B");
  pb.val(var_B) = value_B;

  libsnark::pb_variable<FieldT> var_is_right;
  var_is_right.allocate(pb, "var_is_right");
  pb.val(var_is_right) = is_right;

  merkle_path_selector<FieldT> selector(pb, var_A, var_B, var_is_right, "test_merkle_path_selector");

  selector.generate_r1cs_witness();
  selector.generate_r1cs_constraints();

  if (is_right) {
    if ((pb.val(selector.get_left()) != value_B) && (pb.val(selector.get_right()) != value_A)) {
      return false;
    }
  } else {
    if ((pb.val(selector.get_left()) != value_A) && (pb.val(selector.get_right()) != value_B)) {
      return false;
    }
  }

  if (!pb.is_satisfied()) {
    std::cerr << "FAIL merkle_path_authenticator is_satisfied" << std::endl;
    return false;
  }

  return true;
}

bool test_merkle_path_authenticator_depth1() {
  libsnark::protoboard<FieldT> pb;

  // Tree depth is 1 for this test
  size_t tree_depth = 1;

  // left leaf: 3703141493535563179657531719960160174296085208671919316200479060314459804651,
  // right leaf: 134551314051432487569247388144051420116740427803855572138106146683954151557,
  // root: 7121700468981037559893852455893095765125417767594185027454590493596569372187
  FieldT left = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651");
  FieldT right = FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557");
  FieldT root = FieldT("7121700468981037559893852455893095765125417767594185027454590493596569372187");

  // Set the authenticator for right leaf (`is_right` = 1)
  FieldT is_right = 1;

  libsnark::pb_variable<FieldT> expected_root;
  expected_root.allocate(pb, "expected_root");
  pb.val(expected_root) = root;
  pb.set_input_sizes(1);

  // Bit representation of the address of the leaf to authenticate (here: 1)
  //
  // Note: In a tree of depth d, there are 2^d leaves
  // Each of them can, then, be given an address/index encoded on d bits.
  libsnark::pb_variable_array<FieldT> address_bits;
  address_bits.allocate(pb, tree_depth, "address_bits");
  pb.val(address_bits[0]) = is_right;

  libsnark::pb_variable_array<FieldT> path;
  path.allocate(pb, 1, "path");
  pb.val(path[0]) = left;

  libsnark::pb_variable<FieldT> leaf;
  leaf.allocate(pb, "leaf");
  pb.val(leaf) = right;

  libsnark::pb_variable<FieldT> enforce_bit;
  enforce_bit.allocate(pb, "enforce_bit");
  pb.val(enforce_bit) = FieldT("1");

  merkle_path_authenticator<FieldT, HashTreeT> auth(
    pb,
    tree_depth,
    address_bits,
    leaf,
    expected_root,
    path,
    enforce_bit,
    "authenticator"
  );

  auth.generate_r1cs_constraints();
  auth.generate_r1cs_witness();

  if(!auth.is_valid()) {
    std::cerr << "Not valid!" << std::endl;
    std::cerr << "Expected "; pb.val(expected_root).print();
    std::cerr << "Actual "; pb.val(auth.result()).print();
    return false;
  }

  if(!pb.is_satisfied()) {
    std::cerr << "Constraint system not satisfied!" << std::endl;
    return false;
  }

  return true;
}

bool test_merkle_path_authenticator_depth3() {
  libsnark::protoboard<FieldT> pb;

  // Tree depth is 3 for this test
  size_t tree_depth = 3;

  // We want to authenticate `right0`
  // Thus, we want to check that hash(left2, hash(left1, hash(left0, right0))) == root
  // Where leftX (resp. rightX) denotes the left (resp. right) leaf at level X in
  // the tree (starting from the leaf level being 0)
  FieldT left0 = FieldT("0");
  FieldT right0 = FieldT("0");
  FieldT left1 = FieldT("11714008893116939441510788599557636816518527327543193374630310875272509334396");
  FieldT left2 = FieldT("9881790034808292405036271961589462686158587796044671417688221824074647491645");
  FieldT root = FieldT("13476730430097836153970274382710787532919044453117948373701924629587143655224");
  FieldT is_right = 1;

  // Bit representation of the leaf to authenticate
  // (here: (111)_2 = (7)_10) (_X denote encoding in base X)
  libsnark::pb_variable_array<FieldT> address_bits;
  address_bits.allocate(pb, tree_depth, "address_bits");
  pb.val(address_bits[0]) = is_right;
  pb.val(address_bits[1]) = is_right;
  pb.val(address_bits[2]) = is_right;

  libsnark::pb_variable_array<FieldT> path;
  path.allocate(pb, 3, "path");
  pb.val(path[0]) = left0;
  pb.val(path[1]) = left1;
  pb.val(path[2]) = left2;

  libsnark::pb_variable<FieldT> leaf;
  leaf.allocate(pb, "leaf");
  pb.val(leaf) = right0;

  libsnark::pb_variable<FieldT> expected_root;
  expected_root.allocate(pb, "expected_root");
  pb.val(expected_root) = root;

  libsnark::pb_variable<FieldT> enforce_bit;
  enforce_bit.allocate(pb, "enforce_bit");
  pb.val(enforce_bit) = FieldT("1");

  merkle_path_authenticator<FieldT, HashTreeT> auth(
    pb,
    tree_depth,
    address_bits,
    leaf,
    expected_root,
    path,
    enforce_bit,
    "authenticator"
  );

  auth.generate_r1cs_constraints();
  auth.generate_r1cs_witness();

  if(!auth.is_valid()) {
    std::cerr << "Not valid!" << std::endl;
    std::cerr << "Expected "; pb.val(expected_root).print();
    std::cerr << "Actual "; pb.val(auth.result()).print();
    return false;
  }

  if(!pb.is_satisfied()) {
    std::cerr << "Not satisfied!" << std::endl;
    return false;
  }

  return true;
}

TEST(MainTests, TestMerkleTreeField) {
  bool res = false;

  res = test_merkle_path_selector(0);
  std::cout << "[test_merkle_path_selector 0] Expected (True), Obtained result: " << res << std::endl;
  ASSERT_TRUE(res);

  res = test_merkle_path_selector(1);
  std::cout << "[test_merkle_path_selector 1] Expected (True), Obtained result: " << res << std::endl;
  ASSERT_TRUE(res);

  res = test_merkle_path_authenticator_depth1();
  std::cout << "[test_merkle_path_authenticator_depth1] Expected (True), Obtained result: " << res << std::endl;
  ASSERT_TRUE(res);

  res = test_merkle_path_authenticator_depth3();
  std::cout << "[test_merkle_path_authenticator_depth3] Expected (True), Obtained result: " << res << std::endl;
  ASSERT_TRUE(res);
}

} // namespace

int main(int argc, char **argv) {
  ppT::init_public_params(); // /!\ WARNING: Do once for all tests. Do not forget to do this !!!!
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
