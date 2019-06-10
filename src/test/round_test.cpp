#include "gtest/gtest.h"

#include "snarks_alias.hpp"
#include "circuits/circuits-util.hpp"
#include "circuits/mimc/round.hpp"

#include <libff/common/default_types/ec_pp.hpp>

// Used to instantiate our templates
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libff/algebra/curves/public_params.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

using namespace libsnark;
using namespace libzeth;

namespace  {

    // Testing that (15212  + 98645 + 216319)**7 = 427778066313557225181231220812180094976
    TEST(TestRound, TestTrueNoAddKToResult) {
        //default_r1cs_ppzksnark_pp::init_public_params();
        ppT::init_public_params();
        ProtoboardT pb;

        const VariableT in_x = make_variable(pb, FieldT("15212"), "x");
        const VariableT in_k = make_variable(pb, FieldT("98645"), "k");
        const FieldT in_C = FieldT("216319");

        pb.set_input_sizes(2);

        MiMCe7_round_gadget round_gadget(pb, in_x, in_k, in_C, false, "round_gadget");
        round_gadget.generate_r1cs_witness();
        round_gadget.generate_r1cs_constraints();

        FieldT expected_out = FieldT("427778066313557225181231220812180094976");

        ASSERT_TRUE(expected_out == pb.val(round_gadget.result()));
        ASSERT_TRUE(pb.is_satisfied());
    }

    // Testing that (15212  + 98645 + 216319)**7 + 98645 = 427778066313557225181231220812180193621
    TEST(TestRound, TestTrueAddKToResult) {
        ppT::init_public_params();
        ProtoboardT pb;

        const VariableT in_x = make_variable(pb, FieldT("15212"), "x");
        const VariableT in_k = make_variable(pb, FieldT("98645"), "k");
        const FieldT in_C = FieldT("216319");

        pb.set_input_sizes(2);

        MiMCe7_round_gadget round_gadget(pb, in_x, in_k, in_C, true, "round_gadget");

        round_gadget.generate_r1cs_witness();
        round_gadget.generate_r1cs_constraints();

        FieldT expected_out = FieldT("427778066313557225181231220812180193621");

        ASSERT_TRUE(expected_out == pb.val(round_gadget.result()));
        ASSERT_TRUE(pb.is_satisfied());
    }

}
