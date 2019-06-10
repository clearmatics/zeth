#include "gtest/gtest.h"

#include "snarks_alias.hpp"
#include "circuits/circuits-util.hpp"
#include "circuits/mimc/mimc_hash.hpp"

#include <libff/common/default_types/ec_pp.hpp>

// Used to instantiate our templates
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libff/algebra/curves/public_params.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

using namespace libsnark;
using namespace libzeth;

namespace  {

    TEST(TestMiMCHash, TestTrue) {
        ppT::init_public_params();

        ProtoboardT pb;

        // Public inputs
        VariableT m_0 = make_variable(pb, FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651"), "m_0");
        VariableT m_1 = make_variable(pb, FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557"), "m_1");
        pb.set_input_sizes(2);

        // Private inputs
        VariableT iv = make_variable(pb, FieldT("918403109389145570117360101535982733651217667914747213867238065296420114726"), "iv");
        MiMC_hash_gadget mimc_hash_gadget(pb, iv, {m_0, m_1}, "gadget");

        mimc_hash_gadget.generate_r1cs_witness();
        mimc_hash_gadget.generate_r1cs_constraints();

        FieldT expected_out = FieldT("15683951496311901749339509118960676303290224812129752890706581988986633412003");
        std::cout<<"RESULT:";
        pb.val(mimc_hash_gadget.result()).as_bigint().print();
        ASSERT_TRUE(expected_out == pb.val(mimc_hash_gadget.result()));
        ASSERT_TRUE(pb.is_satisfied());
    }
}
