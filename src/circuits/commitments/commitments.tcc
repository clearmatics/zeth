#ifndef __ZETH_COMMITMENT_CIRCUITS_TCC__
#define __ZETH_COMMITMENT_CIRCUITS_TCC__

// DISCLAIMER: 
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/commitment.tcc

namespace libzeth {

template<typename FieldT>
COMM_gadget<FieldT>::COMM_gadget(libsnark::protoboard<FieldT>& pb,
                                 libsnark::pb_variable<FieldT>& /* ZERO */,
                                 libsnark::pb_variable_array<FieldT> x,
                                 libsnark::pb_variable_array<FieldT> y,
                                 std::shared_ptr<libsnark::digest_variable<FieldT>> result,
                                 const std::string &annotation_prefix
) : libsnark::gadget<FieldT>(pb), result(result)
{
    const std::string annotation_block = std::string("COMM_block-") + annotation_prefix;
    const std::string annotation_hasher = std::string("COMM_ethereum_hasher-") + annotation_prefix;

    block.reset(new libsnark::block_variable<FieldT>(pb, {
        x,
        y
    }, annotation_block));

    hasher.reset(new sha256_ethereum<FieldT>(
        pb,
        libsnark::SHA256_block_size,
        *block,
        *result,
        annotation_hasher
    ));
}

template<typename FieldT>
void COMM_gadget<FieldT>::generate_r1cs_constraints() {
    hasher->generate_r1cs_constraints(true); // ensure_output_bitness set to true
}

template<typename FieldT>
void COMM_gadget<FieldT>::generate_r1cs_witness() {
    hasher->generate_r1cs_witness();
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get128bits(
    libsnark::pb_variable_array<FieldT>& inner_k
) {
    libsnark::pb_variable_array<FieldT> ret;

    // Should always be satisfied
    // Sanity check to avoid going out of bound
    // in the for loop below
    assert(inner_k.size() > 128);

    for(int i = 0; i < 128; i++) {
        ret.emplace_back(inner_k[i]);
    }

    // Check that we correctly built a 128-bit string
    assert(ret.size() == 128);

    return ret;
}

// As mentioned in Zerocash extended paper, page 22
// Right side of the hash inputs to generate cm is
// 0^192 || value_v (64 bits)
template<typename FieldT>
libsnark::pb_variable_array<FieldT> getRightSideCMCOMM(
    libsnark::pb_variable<FieldT>& ZERO,
    libsnark::pb_variable_array<FieldT>& value_v
) {
    libsnark::pb_variable_array<FieldT> right_side;

    // Prepend the value with 192 '0' bits
    for(int i = 0; i < 192; i++) {
        right_side.emplace_back(ZERO);
    }

    for (size_t i = 0; i < value_v.size(); ++i)
    {
        right_side.emplace_back(value_v[i]);
    }

    // Check that we correctly built a 256-bit string
    assert(right_side.size() == 256);

    return right_side;
}

// TODO: Implement the COMM_k_gadget as a 2 hash rounds in order to directly get the
// value of the commitment_k without needing 2 distinct gadgets for this
// Note that the value of the commitment_k needs to be accessible/retreivable as it
// is used as argument of the deposit function call to check the value of the commitment
//
// See Zerocash extended paper, page 22
// The commitment k is computed as k = sha256(r || [sha256(a_pk || rho)]_128)
// where we define the left part: inner_k = sha256(a_pk || rho)
// as being the inner commitment of k
template<typename FieldT>
COMM_inner_k_gadget<FieldT>::COMM_inner_k_gadget(libsnark::protoboard<FieldT>& pb,
                                                libsnark::pb_variable<FieldT>& ZERO,
                                                libsnark::pb_variable_array<FieldT>& a_pk, // 256 bits
                                                libsnark::pb_variable_array<FieldT>& rho, // 256 bits
                                                std::shared_ptr<libsnark::digest_variable<FieldT>> result,
                                                const std::string &annotation_prefix
) : COMM_gadget<FieldT>(pb, ZERO, a_pk, rho, result, annotation_prefix) 
{
    // Nothing
}

// See Zerocash extended paper, page 22
// The commitment k is computed as k = sha256(r || [sha256(a_pk || rho)]_128)
// where we define: outer_k = sha256(r || [inner_commitment]_128)
// as being the outer commitment of k
// We denote by trap_r the trapdoor r
template<typename FieldT>
COMM_outer_k_gadget<FieldT>::COMM_outer_k_gadget(libsnark::protoboard<FieldT>& pb,
                                                libsnark::pb_variable<FieldT>& ZERO,
                                                libsnark::pb_variable_array<FieldT>& trap_r, // 384 bits
                                                libsnark::pb_variable_array<FieldT>& inner_k, // 256 bits, but we only keep 128 bits our of it
                                                std::shared_ptr<libsnark::digest_variable<FieldT>> result,
                                                const std::string &annotation_prefix
) : COMM_gadget<FieldT>(pb, ZERO, trap_r, get128bits(inner_k), result, annotation_prefix)
{
    // Nothing
}

// cm = sha256(outer_k || 0^192 || value_v)
template<typename FieldT>
COMM_cm_gadget<FieldT>::COMM_cm_gadget(libsnark::protoboard<FieldT>& pb,
                                    libsnark::pb_variable<FieldT>& ZERO,
                                    libsnark::pb_variable_array<FieldT>& outer_k,
                                    libsnark::pb_variable_array<FieldT>& value_v, // 64 bits
                                    std::shared_ptr<libsnark::digest_variable<FieldT>> result,
                                    const std::string &annotation_prefix
) : COMM_gadget<FieldT>(pb, ZERO, outer_k, getRightSideCMCOMM(ZERO, value_v), result, annotation_prefix) 
{
    // Nothing
}

} // libzeth

#endif // __ZETH_COMMITMENT_CIRCUITS_TCC__