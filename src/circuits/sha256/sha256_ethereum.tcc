#ifndef __ZETH_SHA256_ETHEREUM_TCC__
#define __ZETH_SHA256_ETHEREUM_TCC__

// DISCLAIMER:
// Content taken and adapted from:
// https://gist.github.com/kobigurk/24c25e68219df87c348f1a78db51bb52

// Get the from_bits function
#include "circuits/circuits-util.hpp"

namespace libzeth {

// See: https://github.com/ethereum/go-ethereum/blob/master/core/vm/contracts.go#L115
// For the implementation of the sha256 precompiled on ethereum, which basically calls the functions from the crypto/sha256 go package:
// https://golang.org/src/crypto/sha256/sha256.go?s=5778:5813#L263
// Where we see that, the function that interests us is "func (d *digest) checkSum() [Size]byte"

template<typename FieldT>
sha256_ethereum<FieldT>::sha256_ethereum(libsnark::protoboard<FieldT> &pb,
                                         const size_t /* block_length */,
                                         const libsnark::block_variable<FieldT> &input_block,
                                         const libsnark::digest_variable<FieldT> &output,
                                         const std::string &annotation_prefix) :
    libsnark::gadget<FieldT>(pb, annotation_prefix)
{
    intermediate_hash.reset(new libsnark::digest_variable<FieldT>(pb, 256, "intermediate"));

    // Set the zero variable to the zero of our field, to later transform
    // boolean vectors into vectors of ONE and ZERO intemplate<typename FieldT>
    //
    // TODO: pass ZERO as argument and delete these instructions. 
    // It should alredy be allocated on the protoboard which is given as argument of this function
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "ZERO");
    pb.val(ZERO) = FieldT::zero(); // Here we want pb.val(ZERO) = 0;

    // Padding
    // Equivalent to the lines
    // -- Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
    // -- var tmp [64]byte
    // -- tmp[0] = 0x80
    // written in the checkSum function of the crypto/sha256 go package
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
    // Note: The IV defined in libsnark is made of:
    // "0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19"
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
    const std::string annotation_hasher1 = std::string("hasher1-") + annotation_prefix;
    const std::string annotation_hasher2 = std::string("hasher2-") + annotation_prefix;
    hasher1.reset(new libsnark::sha256_compression_function_gadget<FieldT>(
                pb, // protoboard
                IV, // previous output - Here the IV
                input_block.bits, // new block
                *intermediate_hash, // output
                annotation_hasher1 // annotation
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
                annotation_hasher2
                )
            );
}

template<typename FieldT>
void sha256_ethereum<FieldT>::generate_r1cs_constraints(const bool ensure_output_bitness)
{
    libff::UNUSED(ensure_output_bitness);
    hasher1->generate_r1cs_constraints();
    hasher2->generate_r1cs_constraints();
}

template<typename FieldT>
void sha256_ethereum<FieldT>::generate_r1cs_witness()
{
    hasher1->generate_r1cs_witness();
    hasher2->generate_r1cs_witness();
}

template<typename FieldT>
size_t sha256_ethereum<FieldT>::get_digest_len()
{
    return SHA256_ETH_digest_size;
}

template<typename FieldT>
size_t sha256_ethereum<FieldT>::get_block_len()
{
    return SHA256_ETH_block_size;
}

template<typename FieldT>
size_t sha256_ethereum<FieldT>::expected_constraints(const bool ensure_output_bitness)
{
    libff::UNUSED(ensure_output_bitness);
    return 54560;
}

template<typename FieldT>
libff::bit_vector sha256_ethereum<FieldT>::get_hash(const libff::bit_vector &input)
{
    libsnark::protoboard<FieldT> pb;

    libsnark::block_variable<FieldT> input_variable(pb, libsnark::SHA256_block_size, "input");
    libsnark::digest_variable<FieldT> output_variable(pb, libsnark::SHA256_digest_size, "output");
    sha256_ethereum<FieldT> eth_hasher(pb, libsnark::SHA256_block_size, input_variable, output_variable, "eth_hasher_gadget");

    input_variable.generate_r1cs_witness(input);
    eth_hasher.generate_r1cs_witness();

    return output_variable.get_digest();
}

} // libzeth

#endif // __ZETH_SHA256_ETHEREUM_TCC__
