#include "gtest/gtest.h"

#include "snarks_alias.hpp"
#include "circuits/circuits-util.hpp"
#include "circuits/mimc/mimc_hash.hpp"
#include "circuit-wrapper.hpp"


#include <libff/common/default_types/ec_pp.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

// Used to instantiate our templates
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libff/algebra/curves/public_params.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

using namespace libsnark;
using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;

namespace  {

    TEST(TestMiMCHash, TestTrue) {
        ppT::init_public_params();

        libsnark::protoboard<FieldT> pb;

        // Public input
        libsnark::pb_variable<FieldT> out;
        libsnark::pb_variable<FieldT> iv;

        out.allocate(pb, "out");
        iv.allocate(pb, "iv");

        pb.set_input_sizes(1);

        pb.val(out) = FieldT("15683951496311901749339509118960676303290224812129752890706581988986633412003");
        pb.val(iv) = FieldT("918403109389145570117360101535982733651217667914747213867238065296420114726");

        // Private inputs

        libsnark::pb_variable<FieldT> m_0;
        libsnark::pb_variable<FieldT> m_1;

        m_0.allocate(pb, "m_0");
        m_1.allocate(pb, "m_1");

        std::vector<libsnark::pb_variable<FieldT>> input = {m_0, m_1};

        pb.val(m_0) = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651");
        pb.val(m_1) = FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557");

        MiMC_hash_gadget<FieldT> mimc_hash_gadget(pb, iv, input, out, "gadget");

        mimc_hash_gadget.generate_r1cs_witness();
        mimc_hash_gadget.generate_r1cs_constraints();

        ASSERT_TRUE(pb.is_satisfied());

        keyPairT<ppT> keypair = libzeth::gen_trusted_setup<ppT>(pb);
        proofT<ppT> proof = libzeth::gen_proof<ppT>(pb, keypair.pk);
        libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input = pb.primary_input();
        extended_proof<ppT> ext_proof = extended_proof<ppT>(proof, primary_input);

        libzeth::verificationKeyT<ppT> vk = keypair.vk;
        bool res = libzeth::verify(ext_proof, vk);

        ASSERT_TRUE(res);
        }

    TEST(TestMiMCHash, TestFalse) {
        ppT::init_public_params();

        libsnark::protoboard<FieldT> pb;

        // Public input
        libsnark::pb_variable<FieldT> out;
        libsnark::pb_variable<FieldT> iv;

        out.allocate(pb, "out");
        iv.allocate(pb, "iv");

        pb.set_input_sizes(1);

        pb.val(out) = FieldT("1568395149631");
        pb.val(iv) = FieldT("918403109389145570117360101535982733651217667914747213867238065296420114726");

        // Private inputs

        libsnark::pb_variable<FieldT> m_0;
        libsnark::pb_variable<FieldT> m_1;

        m_0.allocate(pb, "m_0");
        m_1.allocate(pb, "m_1");

        std::vector<libsnark::pb_variable<FieldT>> input = {m_0, m_1};

        pb.val(m_0) = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651");
        pb.val(m_1) = FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557");

        MiMC_hash_gadget<FieldT> mimc_hash_gadget(pb, iv, input, out, "gadget");

        mimc_hash_gadget.generate_r1cs_witness();
        mimc_hash_gadget.generate_r1cs_constraints();

        ASSERT_FALSE(pb.is_satisfied());

        keyPairT<ppT> keypair = libzeth::gen_trusted_setup<ppT>(pb);
        proofT<ppT> proof = libzeth::gen_proof<ppT>(pb, keypair.pk);
        libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input = pb.primary_input();
        extended_proof<ppT> ext_proof = extended_proof<ppT>(proof, primary_input);

        libzeth::verificationKeyT<ppT> vk = keypair.vk;
        bool res = libzeth::verify(ext_proof, vk);

        ASSERT_FALSE(res);
    }
}
