#ifndef __ZETH_BLAKE2S_HASH_HPP__
#define __ZETH_BLAKE2S_HASH_HPP__

#include "circuits/circuits-util.hpp"
#include "circuits/simple_gadgets.hpp"
#include "g_primitive.hpp"
#include "types/bits.hpp"
#include "util.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <math.h>

namespace libzeth
{

const size_t BLAKE2s_digest_size = 256;
const size_t BLAKE2s_block_size = 512;

template<typename FieldT>
class BLAKE2s_256_comp : public libsnark::gadget<FieldT>
{
private:
    static const int rounds = 10;
    std::array<std::array<FieldT, 32>, 8> h;
    std::array<std::array<FieldT, 32>, 2> t;
    std::array<libsnark::pb_variable_array<FieldT>, 16> block;
    std::array<std::array<libsnark::pb_variable_array<FieldT>, 16>, rounds + 1>
        v;
    std::array<std::array<libsnark::pb_variable_array<FieldT>, 16>, rounds>
        v_temp;
    std::array<libsnark::pb_variable_array<FieldT>, 8> output_bytes;
    libsnark::block_variable<FieldT> input_block;
    libsnark::digest_variable<FieldT> output;

    std::array<std::vector<g_primitive<FieldT>>, 10> g_arrays;
    std::vector<xor_constant_gadget<FieldT>> xor_vector;

    // TODO: Remove ZERO and pass it in the constructor
    libsnark::pb_variable<FieldT> ZERO;

public:
    std::array<std::array<FieldT, 32>, 8> IV;
    std::array<std::array<uint, 16>, 10> sigma;

    BLAKE2s_256_comp(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::block_variable<FieldT> &input_block,
        const libsnark::digest_variable<FieldT> &output,
        const std::string &annotation_prefix = "blake2s_compression_gadget");

    void generate_r1cs_constraints(const bool ensure_output_bitness = true);
    void generate_r1cs_witness();

    static size_t get_block_len();
    static size_t get_digest_len();
    static libff::bit_vector get_hash(const libff::bit_vector &input);

    static size_t expected_constraints(const bool ensure_output_bitness);

    // Helper functions
    void setup_constants();
    void setup_h();
    void setup_counter(size_t len_input_block);
    void setup_v();
    void setup_gadgets();
};

} // namespace libzeth
#include "blake2s_comp.tcc"
#include "blake2s_setup.tcc"

#endif // __ZETH_BLAKE2S_HASH_HPP__