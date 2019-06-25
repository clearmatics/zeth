#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>
#include "circuits/mimc/mimc_hash.hpp"


using namespace libsnark;
using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;

namespace  {

    TEST(TestMiMCHash, TestTrue) {
        ppT::init_public_params();

        libsnark::protoboard<FieldT> pb;

        // Public input
        libsnark::pb_variable<FieldT> iv;

        iv.allocate(pb, "iv");

        pb.set_input_sizes(1);

        pb.val(iv) = FieldT("82724731331859054037315113496710413141112897654334566532528783843265082629790");
        // sha3("Clearmatics"): 14220067918847996031108144435763672811050758065945364308986253046354060608451
        // sha3("Clearmatics_add"): 7655352919458297598499032567765357605187604397960652899494713742188031353302
        // sha3("Clearmatics_sn"): 38594890471543702135425523844252992926779387339253565328142220201141984377400
        // sha3("Clearmatics_pk"): 20715549373167656640519441333099474211916836972862576858009333815040496998894

        // Private inputs

        libsnark::pb_variable<FieldT> m_0;
        libsnark::pb_variable<FieldT> m_1;

        m_0.allocate(pb, "m_0");
        m_1.allocate(pb, "m_1");

        std::vector<libsnark::pb_variable<FieldT>> input = {m_0, m_1};

        pb.val(m_0) = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651");
        pb.val(m_1) = FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557");

        MiMC_hash_gadget<FieldT> mimc_hash_gadget(pb, input, iv, "gadget");

        mimc_hash_gadget.generate_r1cs_witness();
        mimc_hash_gadget.generate_r1cs_constraints();

        FieldT expected_out = FieldT("18800972734388876294699214493377123093998198145242382637648270767389471889403");

        ASSERT_TRUE(expected_out == pb.val(mimc_hash_gadget.result()));
        }


    TEST(TestMiMCHash, TestFalse) {
        ppT::init_public_params();

        libsnark::protoboard<FieldT> pb;

        // Public input
        libsnark::pb_variable<FieldT> iv;

        iv.allocate(pb, "iv");

        pb.set_input_sizes(1);

        pb.val(iv) = FieldT("82724731331859054037315113496710413141112897654334566532528783843265082629790");

        // Private inputs

        libsnark::pb_variable<FieldT> m_0;
        libsnark::pb_variable<FieldT> m_1;

        m_0.allocate(pb, "m_0");
        m_1.allocate(pb, "m_1");

        std::vector<libsnark::pb_variable<FieldT>> input = {m_0, m_1};

        pb.val(m_0) = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651");
        pb.val(m_1) = FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557");

        MiMC_hash_gadget<FieldT> mimc_hash_gadget(pb, input, iv, "gadget");

        mimc_hash_gadget.generate_r1cs_witness();
        mimc_hash_gadget.generate_r1cs_constraints();

        FieldT not_expected_out = FieldT("15683951496311901749339509118960676303290224812129752890706581988986633412003");
        ASSERT_FALSE(not_expected_out == pb.val(mimc_hash_gadget.result()));
    }
}
