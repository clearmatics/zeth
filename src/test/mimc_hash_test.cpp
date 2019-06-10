#include "gtest/gtest.h"

#include "snarks_alias.hpp"
#include "circuits/circuits-util.hpp"
#include "circuits/mimc/mimc_hash.hpp"
#include "circuit-wrapper.hpp"


#include <libff/common/default_types/ec_pp.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

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

        // Public input
        pb.set_input_sizes(2);
        VariableT out = make_variable(pb, FieldT("15683951496311901749339509118960676303290224812129752890706581988986633412003"), "out");
        VariableT iv = make_variable(pb, FieldT("918403109389145570117360101535982733651217667914747213867238065296420114726"), "iv");

        VariableT m_0 = make_variable(pb, FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651"), "m_0");
        VariableT m_1 = make_variable(pb, FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557"), "m_1");

        // Private inputs

        MiMC_hash_gadget mimc_hash_gadget(pb, iv, {m_0, m_1}, out, "gadget");

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

        ProtoboardT pb;

        // Public input
        pb.set_input_sizes(2);
        VariableT out = make_variable(pb, FieldT("1568395149631"), "out");
        VariableT iv = make_variable(pb, FieldT("918403109389145570117360101535982733651217667914747213867238065296420114726"), "iv");

        VariableT m_0 = make_variable(pb, FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651"), "m_0");
        VariableT m_1 = make_variable(pb, FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557"), "m_1");

        // Private inputs

        MiMC_hash_gadget mimc_hash_gadget(pb, iv, {m_0, m_1}, out, "gadget");

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
