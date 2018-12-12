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

// See: https://github.com/ethereum/go-ethereum/blob/master/core/vm/contracts.go#L115
// For the implementation of the sha256 precompiled on ethereum, which basically calls the functions from the crypto/sha256 go package:
// https://golang.org/src/crypto/sha256/sha256.go?s=5778:5813#L263
// Where we see that, the function that interests us is "func (d *digest) checkSum() [Size]byte"

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

    // Padding
    // Equivalent if the lines
    // -- Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
    // -- var tmp [64]byte
	// -- tmp[0] = 0x80
    // in the checkSum function of the crypto/sha256 go package 
    libsnark::pb_variable_array<FieldT> length_padding =
        from_bits({
            // Total size of this vector = 512bits
            // First part: 448bits <-> 56bytes
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

            // Last part: 64bits <-> 8bytes
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

    // https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_components.tcc#L35
    // Note: The IV defined in libsnark is made of: "0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19"
    // See: https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_components.tcc#L31
    //
    // This IV, is the same as the one used in the crypto/sha256 (and thus in ethereum), as we can see here:
    // https://github.com/golang/go/blob/master/src/crypto/sha256/sha256.go#L30-L38
    //
    // This instruction sets the IV for the first round of the hash, which is equivalent to the function
    // https://github.com/golang/go/blob/master/src/crypto/sha256/sha256.go#L152
    libsnark::pb_linear_combination_array<FieldT> IV = libsnark::SHA256_default_IV(pb);

    // Gadget for the SHA256 compression function.
    // https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp#L26
    // Hasher hashes a first time the input data with the IV
    //
    // Note: Looking at the golang implementation of sha256, we see that, after the initialization IV
    // We call the d.Write(data) function, and then we call the d.checkSum() function, that itself call d.Write internally
    // See: https://github.com/golang/go/blob/master/src/crypto/sha256/sha256.go#L276-L277
    // Looking into d.Write(), we see that the function calls the block() function
    // Defined here: https://github.com/golang/go/blob/master/src/crypto/sha256/sha256block_decl.go
    // which operates on a pointer of digest (returns nothing, because it only modifies the pointed memory)
    // Then we have: https://github.com/golang/go/blob/master/src/crypto/sha256/sha256block_generic.go
    // that tells us that block is in fact blockGeneric (Remember that Golang supports first class functions!)
    // Then in https://github.com/golang/go/blob/master/src/crypto/sha256/sha256block.go#L78 we see the implementation
    // of blockGeneric (and thus of block()).
    //
    // Back to https://github.com/golang/go/blob/master/src/crypto/sha256/sha256.go#L276-L277
    // We see that we first call "d.Write(data)" that corresponds to the first round of hashing we do with the hasher1
    // Then looking into https://github.com/golang/go/blob/master/src/crypto/sha256/sha256.go#L236
    // We see that d.checkSum() calls d.Write() again, but this time, with the padding!
    // Thus, this corresponds to the second round of hashing we do here with the hasher2.
    hasher1.reset(new libsnark::sha256_compression_function_gadget<FieldT>(
            pb, // protoboard
            IV, // previous output - Here the IV
            input_block.bits, // new block
            *intermediate_hash, // output
            "hasher1" // annotation
        )
    );

    // The intermediate hash obtained as a result of the first hashing round is then used 
    // as IV for the second hashing round
    libsnark::pb_linear_combination_array<FieldT> IV2(intermediate_hash->bits);

    // We hash the intermediate hash wiht the padding.
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

// From_bits() takes a vector of boolean values, and convert this vector of boolean values into a vector of
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