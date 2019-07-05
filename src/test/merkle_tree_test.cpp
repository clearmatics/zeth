#include "gtest/gtest.h"
#include <libff/common/default_types/ec_pp.hpp>
#include "circuits/merkle_tree/merkle_path_selector.hpp"
#include "circuits/merkle_tree/merkle_path_authenticator.hpp"
#include "circuits/mimc/mimc_hash.hpp"

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;

namespace libzeth {

bool test_merkle_path_selector(int is_right)
{
	ppT::init_public_params(); //TODO fix dependency problem, 
	libsnark::protoboard<FieldT> pb;

	FieldT value_A = FieldT("149674538925118052205057075966660054952481571156186698930522557832224430770");
	FieldT value_B = FieldT("9670701465464311903249220692483401938888498641874948577387207195814981706974");

	is_right = is_right ? 1 : 0;

	libsnark::pb_variable<FieldT> var_A;
	var_A.allocate(pb,"var_A");

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

	if( is_right ) {
		if( pb.val(selector.get_left()) != value_B ) {
			return false;
		}
		if( pb.val(selector.get_right()) != value_A ) {
			return false;
		}
	}
	else {
		if( pb.val(selector.get_left()) != value_A ) {
			return false;
		}
		if( pb.val(selector.get_right()) != value_B ) {
			return false;
		}
	}

	if( ! pb.is_satisfied() ) {
		std::cerr << "FAIL merkle_path_authenticator is_satisfied\n";
		return false;
	}

	return true;//stub_test_proof_verify(pb); TODO
}




bool test_merkle_path_authenticator_depth1() {
    // Tree depth is 1, left leaf is 3703141493535563179657531719960160174296085208671919316200479060314459804651,
    // right leaf is 134551314051432487569247388144051420116740427803855572138106146683954151557,
    // root is 3075442268020138823380831368198734873612490112867968717790651410945045657947. Authenticator for right leaf (`is_right` = 1)

	libsnark::protoboard<FieldT> pb;

	libsnark::pb_variable<FieldT> iv;

	iv.allocate(pb, "iv");

	pb.set_input_sizes(1);

	pb.val(iv) = FieldT("82724731331859054037315113496710413141112897654334566532528783843265082629790");

	FieldT left = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651");
	FieldT right = FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557");
	FieldT root = FieldT("15111851447014879833050233394183206021293104970044755574134456851342505158717");
	FieldT is_right = 1;

	libsnark::pb_variable_array<FieldT> address_bits;
	address_bits.allocate(pb, 1, "address_bits");
	pb.val(address_bits[0]) = is_right;

	libsnark::pb_variable_array<FieldT> path;
	path.allocate(pb, 1, "path");
	pb.val(path[0]) = left;

	libsnark::pb_variable<FieldT> leaf;
	leaf.allocate(pb, "leaf");
	pb.val(leaf) = right;

	libsnark::pb_variable<FieldT> expected_root;
	expected_root.allocate(pb, "expected_root");
	pb.val(expected_root) = root;

	libsnark::pb_variable<FieldT> enforce_bit;
	enforce_bit.allocate(pb, "enforce_bit");
	pb.val(enforce_bit) = FieldT("1");


	size_t tree_depth = 1;
	merkle_path_authenticator<MiMC_hash_gadget<FieldT>, FieldT> auth(
		pb, tree_depth, address_bits,
		leaf, expected_root, path, enforce_bit,
		"authenticator");

	auth.generate_r1cs_constraints();
	auth.generate_r1cs_witness();

	if( ! auth.is_valid() ) {
		std::cerr << "Not valid!" << std::endl;
		std::cerr << "Expected "; pb.val(expected_root).print();
		std::cerr << "Actual "; pb.val(auth.result()).print();
		return false;
	}

	if( ! pb.is_satisfied() ) {
		std::cerr << "Not satisfied!" << std::endl;
		return false;
	}

	return true;
}




bool test_merkle_path_authenticator_depth3() {
    // Tree depth is 3, we want to check that hash(left2, hash(left1, hash(left0, right0))) == root

    FieldT left0 = FieldT("0");
    FieldT right0 = FieldT("0");
    FieldT left1 = FieldT("11714008893116939441510788599557636816518527327543193374630310875272509334396");
    FieldT left2 = FieldT("9881790034808292405036271961589462686158587796044671417688221824074647491645");
    FieldT root = FieldT("9595857972030877320006292774266777975489795872080908840946050038220242513239");
    FieldT is_right = 1;

	libsnark::protoboard<FieldT> pb;

	libsnark::pb_variable_array<FieldT> address_bits;
	address_bits.allocate(pb, 3, "address_bits");
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

	size_t tree_depth = 3;
	merkle_path_authenticator<MiMC_hash_gadget<FieldT>, FieldT> auth(
		pb, tree_depth, address_bits,
		leaf, expected_root, path, enforce_bit,
		"authenticator");

	auth.generate_r1cs_constraints();
	auth.generate_r1cs_witness();

	if( ! auth.is_valid() ) {
		std::cerr << "Not valid!" << std::endl;
		std::cerr << "Expected "; pb.val(expected_root).print();
		std::cerr << "Actual "; pb.val(auth.result()).print();
		return false;
	}

	if( ! pb.is_satisfied() ) {
		std::cerr << "Not satisfied!" << std::endl;
		return false;
	}

	return true;
}



TEST(MainTests, ProofGenAndVerifJS2to2) {
    // Run the trusted setup once for all tests, and keep the keypair in memory for the duration of the tests

    bool res = false;

    res = libzeth::test_merkle_path_selector(0);
    std::cout << "[test_merkle_path_selector 0] Expected (True), Obtained result: " << res << std::endl;
    ASSERT_TRUE(res);

    
    res = libzeth::test_merkle_path_selector(1);
    std::cout << "[test_merkle_path_selector 1] Expected (True), Obtained result: " << res << std::endl;
    ASSERT_TRUE(res);
    
    res = libzeth::test_merkle_path_authenticator_depth1();
    std::cout << "[test_merkle_path_authenticator_depth1] Expected (True), Obtained result: " << res << std::endl;
    ASSERT_TRUE(res);

    res = libzeth::test_merkle_path_authenticator_depth3();
    std::cout << "[test_merkle_path_authenticator_depth3] Expected (True), Obtained result: " << res << std::endl;
    ASSERT_TRUE(res);
    
}

int main(int argc, char **argv) {
    ppT::init_public_params(); // /!\ WARNING: Do once for all tests. Do not forget to do this !!!!
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

// namespace libsnark
}
