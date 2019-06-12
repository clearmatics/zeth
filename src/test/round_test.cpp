#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>

#include "snarks_alias.hpp"
#include "circuits/mimc/round.hpp"

using namespace libsnark;
using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;

namespace  {

    // Testing that (15212  + 98645 + 216319)**7 = 427778066313557225181231220812180094976
    TEST(TestRound, TestTrueNoAddKToResult) {
        ppT::init_public_params();
        libsnark::protoboard<FieldT> pb;

        libsnark::pb_variable<FieldT> in_x;
        libsnark::pb_variable<FieldT> in_k;
        FieldT in_C = FieldT("216319");

        in_x.allocate(pb, "x");
        in_k.allocate(pb, "k");

        pb.val(in_x) = FieldT("15212");
        pb.val(in_k) = FieldT("98645");

        MiMCe7_round_gadget<FieldT> round_gadget(pb, in_x, in_k, in_C, false, "round_gadget");
        round_gadget.generate_r1cs_witness();
        round_gadget.generate_r1cs_constraints();

        FieldT expected_out = FieldT("427778066313557225181231220812180094976");

        ASSERT_TRUE(expected_out == pb.val(round_gadget.result()));
    }

    // Testing that (15212  + 98645 + 216319)**7 + 98645 = 427778066313557225181231220812180193621
    TEST(TestRound, TestTrueAddKToResult) {
        ppT::init_public_params();
        libsnark::protoboard<FieldT> pb;

        libsnark::pb_variable<FieldT> in_x;
        libsnark::pb_variable<FieldT> in_k;
        FieldT in_C = FieldT("216319");

        in_x.allocate(pb, "x");
        in_k.allocate(pb, "k");

        pb.val(in_x) = FieldT("15212");
        pb.val(in_k) = FieldT("98645");

        MiMCe7_round_gadget<FieldT> round_gadget(pb, in_x, in_k, in_C, true, "round_gadget");

        round_gadget.generate_r1cs_witness();
        round_gadget.generate_r1cs_constraints();

        FieldT expected_out = FieldT("427778066313557225181231220812180193621");

        ASSERT_TRUE(expected_out == pb.val(round_gadget.result()));
    }

    TEST(TestRound, TestFalseNoAddKToResult) {
        ppT::init_public_params();
        libsnark::protoboard<FieldT> pb;

        libsnark::pb_variable<FieldT> in_x;
        libsnark::pb_variable<FieldT> in_k;
        FieldT in_C = FieldT("216319");

        in_x.allocate(pb, "x");
        in_k.allocate(pb, "k");

        pb.val(in_x) = FieldT("15212");
        pb.val(in_k) = FieldT("98645");

        MiMCe7_round_gadget<FieldT> round_gadget(pb, in_x, in_k, in_C, false, "round_gadget");
        round_gadget.generate_r1cs_witness();
        round_gadget.generate_r1cs_constraints();

        FieldT expected_out = FieldT("4277780663135572251");

        ASSERT_FALSE(expected_out == pb.val(round_gadget.result()));
    }


    TEST(TestRound, TestFalseAddKToResult) {
        ppT::init_public_params();
        libsnark::protoboard<FieldT> pb;

        libsnark::pb_variable<FieldT> in_x;
        libsnark::pb_variable<FieldT> in_k;
        FieldT in_C = FieldT("216319");

        in_x.allocate(pb, "x");
        in_k.allocate(pb, "k");

        pb.val(in_x) = FieldT("15212");
        pb.val(in_k) = FieldT("98645");

        MiMCe7_round_gadget<FieldT> round_gadget(pb, in_x, in_k, in_C, true, "round_gadget");

        round_gadget.generate_r1cs_witness();
        round_gadget.generate_r1cs_constraints();

        FieldT expected_out = FieldT("42777806631355722518123");

        ASSERT_FALSE(expected_out == pb.val(round_gadget.result()));
    }
}
