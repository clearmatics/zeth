#include "util.hpp"

#include "gtest/gtest.h"
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Access zeth configuration constants
#include "zeth.h"

// Include the type we need
#include "circuits/circuits-utils.hpp"
#include "circuits/notes/note.hpp"
#include "types/bits.hpp"
#include "types/joinsplit.hpp"
#include "types/note.hpp"

using namespace libzeth;

typedef libff::default_ec_pp ppT;

// Should be alt_bn128 in the CMakeLists.txt
typedef libff::Fr<ppT> FieldT;

namespace
{

TEST(TestPackedAddition, TestPackedAddition1)
{
    libff::print_header(
        "Starting test: LHS => value_left1 = 0x000000000000000A, value_left2 = "
        "0x000000000000000A || RHS => value_right1 = 0x0000000000000014");

    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    // === Set the constraints
    libsnark::pb_variable_array<FieldT> value_left1;
    value_left1.allocate(pb, 64, "value_left1");
    libsnark::pb_variable_array<FieldT> value_left2;
    value_left2.allocate(pb, 64, "value_left2");

    libsnark::pb_variable_array<FieldT> value_right1;
    value_right1.allocate(pb, 64, "value_right1");

    libsnark::linear_combination<FieldT> left_side =
        packed_addition(value_left1) + packed_addition(value_left2);
    libsnark::linear_combination<FieldT> right_side =
        packed_addition(value_right1);

    // Constraint to ensure that both sides are equal
    pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(1, left_side, right_side),
        "equality");

    // === Witness
    value_left1.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("000000000000000A")));
    value_left2.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("000000000000000A")));

    // 0A + 0A = 14 in hexa
    value_right1.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("0000000000000014")));

    bool witness_bool = pb.is_satisfied();
    std::cout << "************* SAT result: " << witness_bool
              << " ******************" << std::endl;
    ASSERT_TRUE(witness_bool);
};

TEST(TestPackedAddition, TestPackedAddition2)
{
    libff::print_header(
        "Starting test: LHS => value_left1 = 0x3782DACE9D900000, value_left2 = "
        "0x3782DACE9D900000 || RHS => value_right1 = 0x6124FEE993BC0000, "
        "value_right2 = 0x0DE0B6B3A7640000");

    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    // === Set the constraints
    libsnark::pb_variable_array<FieldT> value_left1;
    value_left1.allocate(pb, 64, "value_left1");
    libsnark::pb_variable_array<FieldT> value_left2;
    value_left2.allocate(pb, 64, "value_left2");

    libsnark::pb_variable_array<FieldT> value_right1;
    value_right1.allocate(pb, 64, "value_right1");
    libsnark::pb_variable_array<FieldT> value_right2;
    value_right2.allocate(pb, 64, "value_right2");

    libsnark::linear_combination<FieldT> left_side =
        packed_addition(value_left1);
    left_side = left_side + packed_addition(value_left2);
    libsnark::linear_combination<FieldT> right_side =
        packed_addition(value_right1);
    right_side = right_side + packed_addition(value_right2);

    // Constraint to ensure that both sides are equal
    pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(1, left_side, right_side),
        "equality");

    // === Witness
    std::cout << "[DEBUG] Defining the witnesses" << std::endl;
    // 0x3782DACE9D900000 = 4ETH
    value_left1.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("3782DACE9D900000")));
    // 0x3782DACE9D900000 = 4ETH
    value_left2.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("3782DACE9D900000")));

    // 0x6124FEE993BC0000 = 7ETH
    value_right1.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("6124FEE993BC0000")));
    // 0x0DE0B6B3A7640000 = 1ETH
    value_right2.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("0DE0B6B3A7640000")));

    bool witness_bool = pb.is_satisfied();
    std::cout << "************* SAT result: " << witness_bool
              << " ******************" << std::endl;
    ASSERT_TRUE(witness_bool);
};

TEST(TestPackedAddition, TestPackedAddition3)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    libff::print_header(
        "Starting test: IN => v_pub = 0x0000000000000010, note1 = "
        "0x2F0000000000000F, note2 = 0x0 || OUT => v_pub = 0x000000000000000B, "
        "note1 = 0x1A00000000000012, note2 = 0x1500000000000002");

    // === Set the constraints
    libsnark::pb_variable_array<FieldT> v_pub_in;
    v_pub_in.allocate(pb, 64, "v_pub_in");
    libsnark::pb_variable_array<FieldT> v_pub_out;
    v_pub_out.allocate(pb, 64, "v_pub_out");

    libsnark::pb_variable_array<FieldT> in_val_note1;
    in_val_note1.allocate(pb, 64, "in_val_note1");
    libsnark::pb_variable_array<FieldT> in_val_note2;
    in_val_note2.allocate(pb, 64, "in_val_note2");

    libsnark::pb_variable_array<FieldT> out_val_note1;
    out_val_note1.allocate(pb, 64, "out_val_note1");
    libsnark::pb_variable_array<FieldT> out_val_note2;
    out_val_note2.allocate(pb, 64, "out_val_note2");

    libsnark::linear_combination<FieldT> left_side = packed_addition(v_pub_in);
    left_side = left_side + packed_addition(in_val_note1);
    left_side = left_side + packed_addition(in_val_note2);

    libsnark::linear_combination<FieldT> right_side =
        packed_addition(v_pub_out);
    right_side = right_side + packed_addition(out_val_note1);
    right_side = right_side + packed_addition(out_val_note2);

    // Constraint to ensure that both sides are equal
    pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(1, left_side, right_side),
        "equality");

    // === Witness
    std::cout << "[DEBUG] Defining the witnesses" << std::endl;
    v_pub_in.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("0000000000000010")));
    in_val_note1.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("2F0000000000000F")));
    in_val_note2.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("0000000000000000")));

    v_pub_out.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("000000000000000B")));
    out_val_note1.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("1A00000000000012")));
    out_val_note2.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("1500000000000002")));

    bool witness_bool = pb.is_satisfied();
    std::cout << "************* SAT result: " << witness_bool
              << " ******************" << std::endl;
    ASSERT_TRUE(witness_bool);
};

TEST(TestPackedAddition, TestPackedAddition4)
{
    libff::print_header("Starting test: IN => v_pub = 0xFA80001400000000, "
                        "note1 = 0x0, note2 = 0x0 || OUT => v_pub = 0x0, note1 "
                        "= 0x8530000A00000000, note2 = 0x7550000A00000000");

    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    libff::print_header("Starting Debug test");

    // === Set the constraints
    std::cout << "[DEBUG] variables allocation" << std::endl;
    libsnark::pb_variable_array<FieldT> v_pub_in;
    v_pub_in.allocate(pb, 64, "v_pub_in");
    libsnark::pb_variable_array<FieldT> v_pub_out;
    v_pub_out.allocate(pb, 64, "v_pub_out");

    libsnark::pb_variable_array<FieldT> in_val_note1;
    in_val_note1.allocate(pb, 64, "in_val_note1");
    libsnark::pb_variable_array<FieldT> in_val_note2;
    in_val_note2.allocate(pb, 64, "in_val_note2");

    libsnark::pb_variable_array<FieldT> out_val_note1;
    out_val_note1.allocate(pb, 64, "out_val_note1");
    libsnark::pb_variable_array<FieldT> out_val_note2;
    out_val_note2.allocate(pb, 64, "out_val_note2");

    libsnark::linear_combination<FieldT> left_side = packed_addition(v_pub_in);
    left_side = left_side + packed_addition(in_val_note1);
    left_side = left_side + packed_addition(in_val_note2);

    libsnark::linear_combination<FieldT> right_side =
        packed_addition(v_pub_out);
    right_side = right_side + packed_addition(out_val_note1);
    right_side = right_side + packed_addition(out_val_note2);

    // Constraint to ensure that both sides are equal
    std::cout << "[DEBUG] Defining constraint" << std::endl;
    pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(1, left_side, right_side),
        "equality");

    // === Witness
    std::cout << "[DEBUG] Defining the witnesses" << std::endl;
    // 0xFA80001400000000 = 18.050427392400293888 // ETH
    v_pub_in.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("FA80001400000000")));

    in_val_note1.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("0000000000000000")));
    in_val_note2.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("0000000000000000")));

    v_pub_out.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("0000000000000000")));

    // 0x8530000A00000000 = 9.597170848876199936 ETH
    out_val_note1.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("8530000A00000000")));

    // 0x7550000A00000000 = 8.453256543524093952 ETH
    out_val_note2.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("7550000A00000000")));

    bool witness_bool = pb.is_satisfied();
    std::cout << "************* SAT result: " << witness_bool
              << " ******************" << std::endl;
    ASSERT_TRUE(witness_bool);
};

TEST(TestPackedAddition, TestPackedAddition5)
{
    libff::print_header("Starting test: IN => v_pub = 0x6124FEE993BC0000, "
                        "note1 = 0x0, note2 = 0x0 || OUT => v_pub = 0x0, note1 "
                        "= 0x3782DACE9D900000, note2 = 0x29A2241AF62C0000");

    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    // === Set the constraints
    libsnark::pb_variable_array<FieldT> v_pub_in;
    v_pub_in.allocate(pb, 64, "v_pub_in");
    libsnark::pb_variable_array<FieldT> v_pub_out;
    v_pub_out.allocate(pb, 64, "v_pub_out");

    libsnark::pb_variable_array<FieldT> in_val_note1;
    in_val_note1.allocate(pb, 64, "in_val_note1");
    libsnark::pb_variable_array<FieldT> in_val_note2;
    in_val_note2.allocate(pb, 64, "in_val_note2");

    libsnark::pb_variable_array<FieldT> out_val_note1;
    out_val_note1.allocate(pb, 64, "out_val_note1");
    libsnark::pb_variable_array<FieldT> out_val_note2;
    out_val_note2.allocate(pb, 64, "out_val_note2");

    libsnark::linear_combination<FieldT> left_side = packed_addition(v_pub_in);
    left_side = left_side + packed_addition(in_val_note1);
    left_side = left_side + packed_addition(in_val_note2);

    libsnark::linear_combination<FieldT> right_side =
        packed_addition(v_pub_out);
    right_side = right_side + packed_addition(out_val_note1);
    right_side = right_side + packed_addition(out_val_note2);

    // Constraint to ensure that both sides are equal
    pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(1, left_side, right_side),
        "equality");

    // === Witness
    std::cout << "[DEBUG] Defining the witnesses" << std::endl;
    // 0x6124FEE993BC0000 = 7ETH
    v_pub_in.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("6124FEE993BC0000")));
    in_val_note1.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("0000000000000000")));
    in_val_note2.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("0000000000000000")));

    v_pub_out.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("0000000000000000")));

    // 0x3782DACE9D900000 = 4ETH

    out_val_note1.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("3782DACE9D900000")));

    // 0x29A2241AF62C0000 = 3ETH
    out_val_note2.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("29A2241AF62C0000")));

    bool witness_bool = pb.is_satisfied();
    std::cout << "************* SAT result: " << witness_bool
              << " ******************" << std::endl;
    ASSERT_TRUE(witness_bool);
};

TEST(TestPackedAddition, TestPackedAddition6)
{
    libff::print_header("Starting test: IN => v_pub = 0x6124FEE993BC0000, "
                        "note1 = 0x0, note2 = 0x0 || OUT => v_pub = 0x0, note1 "
                        "= 0x3782DACE9D900001, note2 = 0x29A2241AF62C0000");

    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    // === Set the constraints
    libsnark::pb_variable_array<FieldT> v_pub_in;
    v_pub_in.allocate(pb, 64, "v_pub_in");
    libsnark::pb_variable_array<FieldT> v_pub_out;
    v_pub_out.allocate(pb, 64, "v_pub_out");

    libsnark::pb_variable_array<FieldT> in_val_note1;
    in_val_note1.allocate(pb, 64, "in_val_note1");
    libsnark::pb_variable_array<FieldT> in_val_note2;
    in_val_note2.allocate(pb, 64, "in_val_note2");

    libsnark::pb_variable_array<FieldT> out_val_note1;
    out_val_note1.allocate(pb, 64, "out_val_note1");
    libsnark::pb_variable_array<FieldT> out_val_note2;
    out_val_note2.allocate(pb, 64, "out_val_note2");

    libsnark::linear_combination<FieldT> left_side = packed_addition(v_pub_in);
    left_side = left_side + packed_addition(in_val_note1);
    left_side = left_side + packed_addition(in_val_note2);

    libsnark::linear_combination<FieldT> right_side =
        packed_addition(v_pub_out);
    right_side = right_side + packed_addition(out_val_note1);
    right_side = right_side + packed_addition(out_val_note2);

    // Constraint to ensure that both sides are equal
    pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(1, left_side, right_side),
        "equality");

    // === Witness
    std::cout << "[DEBUG] Defining the witnesses" << std::endl;
    // 0x6124FEE993BC0000 = 7ETH
    v_pub_in.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("6124FEE993BC0000")));
    in_val_note1.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("0000000000000000")));
    in_val_note2.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("0000000000000000")));

    v_pub_out.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("0000000000000000")));

    // 0x3782DACE9D900000 = 4.000000000000000001ETH
    out_val_note1.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("3782DACE9D900001")));

    // 0x29A2241AF62C0000 = 3ETH
    out_val_note2.fill_with_bits(
        pb, libff::bit_vector(hex_str_to_binary_vector("29A2241AF62C0000")));

    bool witness_bool = pb.is_satisfied();
    std::cout << "************* SAT result: " << witness_bool
              << " ******************" << std::endl;

    // The equality constaint should be violated as 1 wei is created out of thin
    // air in this test 7ETH =/= 7.000000000000000001ETH
    ASSERT_FALSE(witness_bool);
};

} // namespace

int main(int argc, char **argv)
{
    // /!\ WARNING: Do once for all tests. Do not
    // forget to do this !!!!
    ppT::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
