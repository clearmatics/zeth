#include "gtest/gtest.h"

#include "snarks_alias.hpp"
#include "circuits/circuits-util.hpp"
#include "circuits/mimc/mimc.hpp"

#include <libff/common/default_types/ec_pp.hpp>

// Used to instantiate our templates
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libff/algebra/curves/public_params.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

using namespace libsnark;
using namespace libzeth;

namespace  {

    // Testing that (15212  + 98645 + 216319)**7 = 427778066313557225181231220812180094976
    TEST(TestRound, TestTrue) {
        //default_r1cs_ppzksnark_pp::init_public_params();
        ppT::init_public_params();
        ProtoboardT pb;

        const VariableT in_x = make_variable(pb, FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651"), "x");
        const VariableT in_k = make_variable(pb, FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557"), "k");

        pb.set_input_sizes(2);

        MiMCe7_permutation_gadget mimc_gadget(pb, in_x, in_k, "mimc_gadget");
        mimc_gadget.generate_r1cs_witness();
        mimc_gadget.generate_r1cs_constraints();

        FieldT expected_out = FieldT("11437467823393790387399137249441941313717686441929791910070352316474327319704");

        ASSERT_TRUE(expected_out == pb.val(mimc_gadget.result()));
        ASSERT_TRUE(pb.is_satisfied());
    }
}
