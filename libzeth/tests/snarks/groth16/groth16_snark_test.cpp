// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/serialization/proto_utils.hpp"
#include "libzeth/serialization/r1cs_variable_assignment_serialization.hpp"
#include "libzeth/snarks/groth16/groth16_snark.hpp"
#include "libzeth/tests/snarks/common_snark_tests.tcc"

#include <boost/filesystem.hpp>
#include <gtest/gtest.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>

boost::filesystem::path g_output_dir = boost::filesystem::path("");

namespace
{

/// Simple function to generate serializations of snark-related data types for
/// groth16. These may not be well-formed, but have known values for testing
/// serialization compatibility in other components. Data is written to a file
/// with the given path.
template<typename ppT> void generate_test_data()
{
    if (g_output_dir.empty()) {
        std::cout << "Skipping groth16 test data output ("
                  << libzeth::pp_name<ppT>() << ")\n";
        return;
    }

    using groth16 = libzeth::groth16_snark<ppT>;
    using Field = libff::Fr<ppT>;
    using G1 = libff::G1<ppT>;
    using G2 = libff::G2<ppT>;
    const std::string curve_name = libzeth::pp_name<ppT>();

    // dummy constraint_system =
    // primary_input = { x1, x2 }, (indices 1, 2)
    // auxiliary_input = { w1, w2, w3 },  (3, 4, 5)
    // constraints = {
    //   (2*x1 + 3*w1) * (4*x2 + 5*w2) = 6*w3 + 7*x1,
    //   (7*x2 + 6*w3) * (5*x1 + 4*w1) = 3*w2 + 2*x2,
    // }
    //
    // (Note that these are constructed "manually" (rather than with a big
    // constructor call) to avoid the sorting in the linear_combination
    // constructor, which makes the order of terms less predictable.
    libsnark::r1cs_constraint_system<Field> cs;

    libsnark::linear_combination<Field> cs1_A;
    cs1_A.add_term({1, 2});
    cs1_A.add_term({3, 3});
    libsnark::linear_combination<Field> cs1_B;
    cs1_B.add_term({2, 4});
    cs1_B.add_term({4, 5});
    libsnark::linear_combination<Field> cs1_C;
    cs1_C.add_term({5, 6});
    cs1_C.add_term({1, 7});
    cs.add_constraint({cs1_A, cs1_B, cs1_C});

    libsnark::linear_combination<Field> cs2_A;
    cs2_A.add_term({2, 7});
    cs2_A.add_term({5, 6});
    libsnark::linear_combination<Field> cs2_B;
    cs2_B.add_term({1, 5});
    cs2_B.add_term({3, 4});
    libsnark::linear_combination<Field> cs2_C;
    cs2_C.add_term({4, 3});
    cs2_C.add_term({2, 2});
    cs.add_constraint({cs2_A, cs2_B, cs2_C});

    cs.primary_input_size = 2;
    cs.auxiliary_input_size = 3;
    {
        std::ofstream out_s(
            (g_output_dir / ("groth16_r1cs_" + curve_name)).c_str(),
            std::ios_base::out | std::ios_base::binary);
        libzeth::r1cs_write_bytes(cs, out_s);
    }

    // Proving key
    const typename groth16::proving_key pk(
        G1::one(),                // alpha_g1 = [1]_1
        -G1::one(),               // beta_g1 = [-1]_1
        -G2::one(),               // beta_g2 = [-1]_2
        -(G1::one() + G1::one()), // beta_g1 = [-2]_1
        -(G2::one() + G2::one()), // beta_g2 = [-2]_2
        libff::G1_vector<ppT>{{
            // A_query = { [7]_1, [-3]_1, [8]_1 }
            Field("7") * G1::one(),
            -Field("3") * G1::one(),
            Field("8") * G1::one(),
        }},
        libsnark::knowledge_commitment_vector<G2, G1>(
            std::vector<libsnark::knowledge_commitment<G2, G1>>{{
                // B_query = { ([9]_1,[9]_2), ([-9]_1,[-9]_2), ([10]_1,[10}_2) }
                libsnark::knowledge_commitment<G2, G1>(
                    Field("9") * G2::one(), Field("9") * G1::one()),
                libsnark::knowledge_commitment<G2, G1>(
                    -Field("9") * G2::one(), -Field("9") * G1::one()),
                libsnark::knowledge_commitment<G2, G1>(
                    Field("10") * G2::one(), Field("10") * G1::one()),
            }}),
        {{
            // H_query = { [11]_1, [-11]_1, [12]_1 }
            Field("11") * G1::one(),
            -Field("11") * G1::one(),
            Field("12") * G1::one(),
        }},
        {{
            // L_query = { [13]_1, [-13]_1, [14]_1 }
            Field("13") * G1::one(),
            -Field("13") * G1::one(),
            Field("14") * G1::one(),
        }},
        std::move(cs));
    {
        std::ofstream out_s(
            (g_output_dir / ("groth16_proving_key_" + curve_name)).c_str(),
            std::ios_base::out | std::ios_base::binary);
        groth16::proving_key_write_bytes(pk, out_s);
    }

    // Verification Key
    const typename groth16::verification_key vk(
        Field("21") * G1::one(),  // alpha_g1 = [21]_1
        -Field("21") * G2::one(), // beta_g2 = [-21]_2
        Field("22") * G2::one(),  // delta_g2 = [22]_2
        libsnark::accumulation_vector<G1>(
            // ABC_g1 = { [13]_1, { [-13]_1, [14]_1 } }
            Field("13") * G1::one(),
            libff::G1_vector<ppT>{{
                -Field("13") * G1::one(),
                Field("14") * G1::one(),
            }}));
    {
        std::ofstream out_s(
            (g_output_dir / ("groth16_verification_key_" + curve_name)).c_str(),
            std::ios_base::out | std::ios_base::binary);
        groth16::verification_key_write_bytes(vk, out_s);
    }

    // Variable assignment
    const libsnark::r1cs_variable_assignment<Field> assignment{{
        Field("15"),
        -Field("15"),
        Field("16"),
        -Field("16"),
        Field("17"),
        -Field("17"),
    }};
    {
        std::ofstream out_s(
            (g_output_dir / ("groth16_assignment_" + curve_name)).c_str(),
            std::ios_base::out | std::ios_base::binary);
        libzeth::r1cs_variable_assignment_write_bytes(assignment, out_s);
    }
}

TEST(Groth16SnarkTest, Groth16TestData)
{
    generate_test_data<libff::alt_bn128_pp>();
    generate_test_data<libff::bls12_377_pp>();
}

TEST(Groth16SnarkTest, TestVerificationKeyReadWriteBytes)
{
    const bool test_alt_bn128 =
        libzeth::tests::verification_key_read_write_bytes_test<
            libff::alt_bn128_pp,
            libzeth::groth16_snark<libff::alt_bn128_pp>>();
    ASSERT_TRUE(test_alt_bn128);
    const bool test_bls12_377 =
        libzeth::tests::verification_key_read_write_bytes_test<
            libff::bls12_377_pp,
            libzeth::groth16_snark<libff::bls12_377_pp>>();
    ASSERT_TRUE(test_bls12_377);
}

TEST(Groth16SnarkTest, TestProvingKeyReadWriteBytes)
{
    const bool test_alt_bn128 =
        libzeth::tests::proving_key_read_write_bytes_test<
            libff::alt_bn128_pp,
            libzeth::groth16_snark<libff::alt_bn128_pp>>();
    ASSERT_TRUE(test_alt_bn128);
    const bool test_bls12_377 =
        libzeth::tests::proving_key_read_write_bytes_test<
            libff::bls12_377_pp,
            libzeth::groth16_snark<libff::bls12_377_pp>>();
    ASSERT_TRUE(test_bls12_377);
}

} // namespace

int main(int argc, char **argv)
{
    libff::alt_bn128_pp::init_public_params();
    libff::bls12_377_pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);

    // Extract the test data destination dir, if passed on the command line.
    if (argc > 1) {
        g_output_dir = boost::filesystem::path(argv[1]);
    }

    return RUN_ALL_TESTS();
}
