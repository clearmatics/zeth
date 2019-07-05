#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

// Header to use the merkle tree data structure
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Used to instantiate our templates
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libff/algebra/curves/public_params.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

// Header to use the mimc_hash gadget
#include "circuits/mimc/mimc_hash.hpp"

// Access the `from_bits` function and other utils
#include "circuits/circuits-util.hpp"
#include "util.hpp"

// Gadget to test
#include "circuits/prfs/prfs.hpp"

using namespace libsnark;
using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT; // Should be alt_bn128 in the CMakeLists.txt

namespace {

TEST(TestPRFs, TestPRFAddrApkGadget) {
    ppT::init_public_params();
    libsnark::protoboard<FieldT> pb;

    libsnark::pb_variable<FieldT> a_sk;

    a_sk.allocate(pb, "a_sk");
    pb.val(a_sk) = FieldT("589222706093357518114482131910849758992408938184976784785865710146974629697"); 
	std::cout << "a sk" << " " << pb.val(a_sk) << std::endl;

    PRF_addr_a_pk_gadget<FieldT> prf_test_gadget(pb, a_sk, "PRF_test_gadget");

    prf_test_gadget.generate_r1cs_constraints();
    prf_test_gadget.generate_r1cs_witness();

    FieldT expected_out = FieldT("19504323340970479201835685154342269193214116474798849891157554964384229851117");
	std::cout << "exp" << " " << expected_out << std::endl;

	std::cout << "res" << " " << pb.val(prf_test_gadget.result()) << std::endl;

    ASSERT_TRUE(expected_out == pb.val(prf_test_gadget.result()));
}


TEST(TestPRFs, TestPRFNfGadget) {
    ppT::init_public_params();
    libsnark::protoboard<FieldT> pb;

    libsnark::pb_variable<FieldT> a_sk;
    libsnark::pb_variable<FieldT> rho;

    a_sk.allocate(pb, "a_sk");
    pb.val(a_sk) = FieldT("851493376840744413073667399677511791313475385900051386471275211952944369427"); 

    rho.allocate(pb, "rho");
    pb.val(rho) = FieldT("12084776370353832975670700397493400375929185577144119428008068929747409552694"); 

    PRF_nf_gadget<FieldT> prf_test_gadget(pb, a_sk, rho, "PRF_test_gadget");

    prf_test_gadget.generate_r1cs_constraints();
    prf_test_gadget.generate_r1cs_witness();

    FieldT expected_out = FieldT("21082003654379266988874215140607791153416686323485087338468105187340220318402");

    ASSERT_TRUE(expected_out == pb.val(prf_test_gadget.result()));
}

} // namespace
