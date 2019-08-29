#include "gtest/gtest.h"

#include <libff/common/default_types/ec_pp.hpp>

#include "snarks_alias.hpp"
#include "circuits/blake2s/g_primitive.hpp"
#include "circuits/blake2s/blake2s_comp.hpp"

// Access the `from_bits` function and other utils
#include "circuits/circuits-util.hpp"
#include "util.hpp"

using namespace libsnark;
using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;

namespace {

// The test correponds to the first round of blake2s(b"hello world")
TEST(TestG, TestTrue) {
    libsnark::protoboard<FieldT> pb;

    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    // 0110 1011  0000 1000 1110 0110  0100 0111
    libsnark::pb_variable_array<FieldT> a = from_bits(
        {
            0, 1, 1, 0, 1, 0, 1, 1,
            0, 0, 0, 0, 1, 0, 0, 0,
            1, 1, 1, 0, 0, 1, 1, 0,
            0, 1, 0, 0, 0, 1, 1, 1
        }, ZERO
    );
    // 0101 0001  0000 1110  0101 0010  0111 1111
    libsnark::pb_variable_array<FieldT> b = from_bits(
        {
            0, 1, 0, 1, 0, 0, 0, 1,
            0, 0, 0, 0, 1, 1, 1, 0,
            0, 1, 0, 1, 0, 0, 1, 0,
            0, 1, 1, 1, 1, 1, 1, 1
        }, ZERO
    );
    // 0110 1010  0000 1001  1110 0110  0110 0111
    libsnark::pb_variable_array<FieldT> c = from_bits(
        {
            0, 1, 1, 0, 1, 0, 1, 0,
            0, 0, 0, 0, 1, 0, 0, 1,
            1, 1, 1, 0, 0, 1, 1, 0,
            0, 1, 1, 0, 0, 1, 1, 1
        }, ZERO
    );
    // 0101 0001  0000 1110  0101 0010  0111 0100
    libsnark::pb_variable_array<FieldT> d = from_bits(
        {
            0, 1, 0, 1, 0, 0, 0, 1,
            0, 0, 0, 0, 1, 1, 1, 0,
            0, 1, 0, 1, 0, 0, 1, 0,
            0, 1, 1, 1, 0, 1, 0, 0
        }, ZERO
    );

    // 0110 1100  0110 1100  0110 0101  0110 1000
    libsnark::pb_variable_array<FieldT> x = from_bits(
        {
            0, 1, 1, 0, 1, 1, 0, 0,
            0, 1, 1, 0, 1, 1, 0, 0,
            0, 1, 1, 0, 0, 1, 0, 1,
            0, 1, 1, 0, 1, 0, 0, 0
        }, ZERO
    );

    // 0110 1111  0111 0111  0010 0000  0110 1111
    libsnark::pb_variable_array<FieldT> y = from_bits(
        {
            0, 1, 1, 0, 1, 1, 1, 1,
            0, 1, 1, 1, 0, 1, 1, 1,
            0, 0, 1, 0, 0, 0, 0, 0,
            0, 1, 1, 0, 1, 1, 1, 1
        }, ZERO
    );

    libsnark::pb_variable_array<FieldT> a2;
    a2.allocate(pb, 32, "a2");

    libsnark::pb_variable_array<FieldT> b2;
    b2.allocate(pb, 32, "b2");

    libsnark::pb_variable_array<FieldT> c2;
    c2.allocate(pb, 32, "c2");

    libsnark::pb_variable_array<FieldT> d2;
    d2.allocate(pb, 32, "d2");

    g_primitive<FieldT> g_gadget(pb, a, b, c, d, x, y, a2, b2, c2, d2);
    g_gadget.generate_r1cs_constraints();
    g_gadget.generate_r1cs_witness();

    // 0111 0000  1011 0001  0011 0101  0011 1101
    libsnark::pb_variable_array<FieldT> a2_expected = from_bits(
        {
            0, 1, 1, 1, 0, 0, 0, 0, 
            1, 0, 1, 1, 0, 0, 0, 1,
            0, 0, 1, 1, 0, 1, 0, 1,
            0, 0, 1, 1, 1, 1, 0, 1
        }, ZERO
    );

    // 1100 0000  0111 1111  0010 1110  0111 1011
    libsnark::pb_variable_array<FieldT> b2_expected = from_bits(
        {
            1, 1, 0, 0, 0, 0, 0, 0,
            0, 1, 1, 1, 1, 1, 1, 1,
            0, 0, 1, 0, 1, 1, 1, 0,
            0, 1, 1, 1, 1, 0, 1, 1
        }, ZERO
    );

    // 1110 0111  0010 0001  0100 1011  0100 0000
    libsnark::pb_variable_array<FieldT> c2_expected = from_bits(
        {
            1, 1, 1, 0, 0, 1, 1, 1,
            0, 0, 1, 0, 0, 0, 0, 1,
            0, 1, 0, 0, 1, 0, 1, 1,
            0, 1, 0, 0, 0, 0, 0, 0
        }, ZERO
    );

    // 1011 0000  1011 1100  1110 1011  0100 1100
    libsnark::pb_variable_array<FieldT> d2_expected = from_bits(
        {
            1, 0, 1, 1, 0, 0, 0, 0,
            1, 0, 1, 1, 1, 1, 0, 0,
            1, 1, 1, 0, 1, 0, 1, 1,
            0, 1, 0, 0, 1, 1, 0, 0
        }, ZERO
    );    
    ASSERT_EQ(a2_expected.get_bits(pb), a2.get_bits(pb));
    ASSERT_EQ(b2_expected.get_bits(pb), b2.get_bits(pb));
    ASSERT_EQ(c2_expected.get_bits(pb), c2.get_bits(pb));
    ASSERT_EQ(d2_expected.get_bits(pb), d2.get_bits(pb));
}

// The test correponds to blake2s(b"hello world")
TEST(TestBlake2sComp, TestTrue) {
    libsnark::protoboard<FieldT> pb;

    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    // b"hello world" in big endian
    libsnark::pb_variable_array<FieldT> pb_va_input = from_bits(
        {
            0, 1, 1, 0, 1, 0, 0, 0, // 68
            0, 1, 1, 0, 0, 1, 0, 1, // 65
            0, 1, 1, 0, 1, 1, 0, 0, // 6C
            0, 1, 1, 0, 1, 1, 0, 0, // 6C
            0, 1, 1, 0, 1, 1, 1, 1, // 6F
            0, 0, 1, 0, 0, 0, 0, 0, // 20
            0, 1, 1, 1, 0, 1, 1, 1, // 77
            0, 1, 1, 0, 1, 1, 1, 1, // 6F
            0, 1, 1, 1, 0, 0, 1, 0, // 72
            0, 1, 1, 0, 1, 1, 0, 0, // 6C
            0, 1, 1, 0, 0, 1, 0, 0, // 64
        }, ZERO
    );

    libsnark::block_variable<FieldT> input(pb, {pb_va_input}, "blake2s_block_input");

    libsnark::digest_variable<FieldT> output(pb, BLAKE2s_digest_size, "output");

    BLAKE2s_256_comp<FieldT> blake2s_comp_gadget(pb, input, output);
    blake2s_comp_gadget.generate_r1cs_constraints();
    blake2s_comp_gadget.generate_r1cs_witness();

    // blake2s(b"hello world")
    libsnark::pb_variable_array<FieldT> expected = from_bits(
        {
            1, 0, 0, 1, 1, 0, 1, 0, // 9A
            1, 1, 1, 0, 1, 1, 0, 0, // EC
            0, 1, 1, 0, 1, 0, 0, 0, // 68
            0, 0, 0, 0, 0, 1, 1, 0, // 06
            0, 1, 1, 1, 1, 0, 0, 1, // 79
            0, 1, 0, 0, 0, 1, 0, 1, // 45
            0, 1, 1, 0, 0, 0, 0, 1, // 61
            0, 0, 0, 1, 0, 0, 0, 0, // 10
            0, 1, 1, 1, 1, 1, 1, 0, // 7E
            0, 1, 0, 1, 1, 0, 0, 1, // 59
            0, 1, 0, 0, 1, 0, 1, 1, // 4B
            0, 0, 0, 1, 1, 1, 1, 1, // 1F
            0, 1, 1, 0, 1, 0, 1, 0, // 6A
            1, 0, 0, 0, 1, 0, 1, 0, // 8A
            0, 1, 1, 0, 1, 0, 1, 1, // 6B
            0, 0, 0, 0, 1, 1, 0, 0, // 0C
            1, 0, 0, 1, 0, 0, 1, 0, // 92
            1, 0, 1, 0, 0, 0, 0, 0, // A0
            1, 1, 0, 0, 1, 0, 1, 1, // CB
            1, 0, 1, 0, 1, 0, 0, 1, // A9
            1, 0, 1, 0, 1, 1, 0, 0, // AC
            1, 1, 1, 1, 0, 1, 0, 1, // F5
            1, 1, 1, 0, 0, 1, 0, 1, // E5
            1, 1, 1, 0, 1, 0, 0, 1, // E9
            0, 0, 1, 1, 1, 1, 0, 0, // 3C
            1, 1, 0, 0, 1, 0, 1, 0, // CA
            0, 0, 0, 0, 0, 1, 1, 0, // 06
            1, 1, 1, 1, 0, 1, 1, 1, // F7
            1, 0, 0, 0, 0, 0, 0, 1, // 81
            1, 0, 0, 0, 0, 0, 0, 1, // 81
            0, 0, 1, 1, 1, 0, 1, 1, // 3B
            0, 0, 0, 0, 1, 0, 1, 1  // 0B
        }, ZERO
    );
   
    ASSERT_EQ(expected.get_bits(pb), output.bits.get_bits(pb));
}

} // namespace

int main(int argc, char **argv) {
    ppT::init_public_params(); // /!\ WARNING: Do once for all tests. Do not forget to do this !!!!
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
