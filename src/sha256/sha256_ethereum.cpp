// Taken from:
// https://gist.github.com/kobigurk/24c25e68219df87c348f1a78db51bb52

#include "sha256_ethereum.hpp"

// This define directive is useless/redundant, as ONE is defined here:
// libsnark/gadgetlib1/pb_variable.hpp#74
// #define ONE libsnark::pb_variable<FieldT>(0)
// 
// We know that a pb_variable takes an index in the constructor:
// See: libsnark/gadgetlib1/pb_variable.hpp#29
// Then the pb_variable can be allocated on the protoboard
// See here for the allocation function: libsnark/gadgetlib1/pb_variable.tcc#19
// This function calls the allocation function of the protoboard: libsnark/gadgetlib1/protoboard.tcc#38
// This function basically allocates the variable on the protoboard at the index defined by the variable
// "next_free_var". It then returns the index the variable was allocated at, and, we can see in
// libsnark/gadgetlib1/pb_variable.tcc#19 that the index of the variable is given by the index where
// the variable was allocated on the protoboard.
// MOREOVER, we see in: libsnark/gadgetlib1/protoboard.tcc#19 (the constructor of the protoboard)
// that "next_free_var = 1; /* to account for constant 1 term *". Thus, the variable at index
// 0 on the protoboard is the constant_term variable, which value is FieldT::one() 
// (which basically is the multiplicative identity of the field FieldT)
// Thus we are safe here. The ONE is well equal to the value FieldT::one()

sha256_ethereum::sha256_ethereum(
    libsnark::protoboard<FieldT> &pb,
    const size_t block_length,
    const libsnark::block_variable<FieldT> &input_block,
    const libsnark::digest_variable<FieldT> &output,
    const std::string &annotation_prefix) : libsnark::gadget<FieldT>(pb, "sha256_ethereum")
{
    intermediate_hash.reset(new libsnark::digest_variable<FieldT>(pb, 256, "intermediate"));
    libsnark::pb_variable<FieldT> ZERO;

    ZERO.allocate(pb, "ZERO");
    pb.val(ZERO) = 0; // Here we want pb.val(ZERO) = FieldT::zero();

    // final padding
    libsnark::pb_variable_array<FieldT> length_padding =
        from_bits({
            // padding
            1,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,

            // length of message (512 bits)
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,1,0,
            0,0,0,0,0,0,0,0
        }, 
        ZERO
    );

    /*
        block2.reset(new block_variable<FieldT>(pb, {
        length_padding
        }, "block2"));
    */
    libsnark::pb_linear_combination_array<FieldT> IV = libsnark::SHA256_default_IV(pb);

    hasher1.reset(new libsnark::sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            input_block.bits,
            *intermediate_hash,
            "hasher1"
        )
    );

    libsnark::pb_linear_combination_array<FieldT> IV2(intermediate_hash->bits);
    // std::cout << block2->bits;
    // std::cout << intermediate_hash;

    hasher2.reset(new libsnark::sha256_compression_function_gadget<FieldT>(
            pb,
            IV2,
            length_padding,
            output,
            "hasher2"
        )
    );
}

void sha256_ethereum::generate_r1cs_constraints(const bool ensure_output_bitness) {
    libff::UNUSED(ensure_output_bitness);
    hasher1->generate_r1cs_constraints();
    hasher2->generate_r1cs_constraints();
}

void sha256_ethereum::generate_r1cs_witness() {
    hasher1->generate_r1cs_witness();
    hasher2->generate_r1cs_witness();
}

size_t sha256_ethereum::get_digest_len() {
    return 256;
}

libff::bit_vector sha256_ethereum::get_hash(const libff::bit_vector &input) {
    libsnark::protoboard<FieldT> pb;

    libsnark::block_variable<FieldT> input_variable(pb, libsnark::SHA256_block_size, "input");
    libsnark::digest_variable<FieldT> output_variable(pb, libsnark::SHA256_digest_size, "output");
    sha256_ethereum f(pb, libsnark::SHA256_block_size, input_variable, output_variable, "f");

    input_variable.generate_r1cs_witness(input);
    f.generate_r1cs_witness();

    return output_variable.get_digest(); 
}

size_t sha256_ethereum::expected_constraints(const bool ensure_output_bitness) {
    libff::UNUSED(ensure_output_bitness);
    return 54560; /* hardcoded for now */
}

std::vector<unsigned long> bit_list_to_ints(std::vector<bool> bit_list, const size_t wordsize) {
    std::vector<unsigned long> res;
	size_t iterations = bit_list.size()/wordsize+1;
    for (size_t i = 0; i < iterations; ++i) {
        unsigned long current = 0;
        for (size_t j = 0; j < wordsize; ++j) {
            if (bit_list.size() == (i*wordsize+j)) break;
            current += (bit_list[i*wordsize+j] * (1ul<<(wordsize-1-j)));
        }
        res.push_back(current);
    }
    return res;
}

// from_bits() takes a vector of boolean values, and convert this vector of boolean values into a vector of
// identities in the field FieldT, where bool(0) <-> ZERO (Additive identity in FieldT), and where
// bool(1) <-> ONE (Multiplicative identity in FieldT)
libsnark::pb_variable_array<FieldT> from_bits(std::vector<bool> bits, libsnark::pb_variable<FieldT>& ZERO) {
    libsnark::pb_variable_array<FieldT> acc;
	for (size_t i = 0; i < bits.size(); i++) {
		bool bit = bits[i];
		acc.emplace_back(bit ? ONE : ZERO);
	}

    return acc;
}
