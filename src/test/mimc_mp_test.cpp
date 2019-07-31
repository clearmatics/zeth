#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>
#include "circuits/mimc/mimc_mp.hpp"


using namespace libsnark;
using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;

namespace  {

    TEST(TestMiMCMp, TestTrue) {
        ppT::init_public_params();

        libsnark::protoboard<FieldT> pb;

        // Public input
        libsnark::pb_variable<FieldT> y;

        y.allocate(pb, "y");

        pb.set_input_sizes(1);

        pb.val(y) = FieldT("15683951496311901749339509118960676303290224812129752890706581988986633412003"); // sha3_256("mimc")

        // Private inputs

        libsnark::pb_variable<FieldT> x;

        x.allocate(pb, "x");

        pb.val(x) = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651");

        MiMC_mp_gadget<FieldT> mimc_mp_gadget(pb, x, y, "gadget");

        mimc_mp_gadget.generate_r1cs_witness();
        mimc_mp_gadget.generate_r1cs_constraints();

        FieldT expected_out = FieldT("16797922449555994684063104214233396200599693715764605878168345782964540311877");

        ASSERT_TRUE(expected_out == pb.val(mimc_mp_gadget.result()));
        }


    TEST(TestMiMCMp, TestFalse) {
        ppT::init_public_params();

        libsnark::protoboard<FieldT> pb;

        // Public input
        libsnark::pb_variable<FieldT> y;

        y.allocate(pb, "y");

        pb.set_input_sizes(1);

        pb.val(y) = FieldT("82724731331859054037315113496710413141112897654334566532528783843265082629790");

        // Private inputs

        libsnark::pb_variable<FieldT> x;
        x.allocate(pb, "x");

        pb.val(x) = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651");

        MiMC_mp_gadget<FieldT> mimc_mp_gadget(pb, x, y, "gadget");

        mimc_mp_gadget.generate_r1cs_witness();
        mimc_mp_gadget.generate_r1cs_constraints();

        FieldT not_expected_out = FieldT("15683951496311901749339509118960676303290224812129752890706581988986633412003");
        ASSERT_FALSE(not_expected_out == pb.val(mimc_mp_gadget.result()));
    }
} // namespace

int main(int argc, char **argv) {
    ppT::init_public_params(); // /!\ WARNING: Do once for all tests. Do not forget to do this !!!!
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
