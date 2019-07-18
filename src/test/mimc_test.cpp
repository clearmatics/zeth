#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>

#include "snarks_alias.hpp"
#include "circuits/mimc/mimc.hpp"

using namespace libsnark;
using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;

namespace {

    TEST(TestRound, TestTrue) {
        ppT::init_public_params();
        libsnark::protoboard<FieldT> pb;

        libsnark::pb_variable<FieldT> in_x;
        libsnark::pb_variable<FieldT> in_k;

        in_x.allocate(pb, "x");
        in_k.allocate(pb, "k");

        pb.val(in_x) = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651");
        pb.val(in_k) = FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557");

        MiMCe7_permutation_gadget<FieldT> mimc_gadget(pb, in_x, in_k, "mimc_gadget");

        mimc_gadget.generate_r1cs_constraints();
        mimc_gadget.generate_r1cs_witness();

        FieldT expected_out = FieldT("11437467823393790387399137249441941313717686441929791910070352316474327319704");

        ASSERT_TRUE(expected_out == pb.val(mimc_gadget.result()));
    }


      TEST(TestRound, TestFalse) {
        ppT::init_public_params();
        libsnark::protoboard<FieldT> pb;

        libsnark::pb_variable<FieldT> in_x;
        libsnark::pb_variable<FieldT> in_k;

        in_x.allocate(pb, "x");
        in_k.allocate(pb, "k");

        pb.val(in_x) = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651");
        pb.val(in_k) = FieldT("13455131405143248756924738814405142");

        MiMCe7_permutation_gadget<FieldT> mimc_gadget(pb, in_x, in_k, "mimc_gadget");

        mimc_gadget.generate_r1cs_witness();
        mimc_gadget.generate_r1cs_constraints();

        FieldT expected_out = FieldT("11437467823393790387399137249441941313717686441929791910070352316474327319704");

        ASSERT_FALSE(expected_out == pb.val(mimc_gadget.result()));
    }
}
