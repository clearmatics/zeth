#ifndef __ZETH_CIRCUITS_COMMITMENT_TCC__
#define __ZETH_CIRCUITS_COMMITMENT_TCC__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/commitment.tcc

namespace libzeth
{

template<typename FieldT, typename HashT>
COMM_gadget<FieldT, HashT>::COMM_gadget(
    libsnark::protoboard<FieldT> &pb,
    libsnark::pb_variable_array<FieldT> x,
    libsnark::pb_variable_array<FieldT> y,
    std::shared_ptr<libsnark::digest_variable<FieldT>> result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix), result(result)
{
    block.reset(new libsnark::block_variable<FieldT>(
        pb, {x, y}, FMT(this->annotation_prefix, " block")));

    hasher.reset(new HashT(
        pb, *block, *result, FMT(this->annotation_prefix, " hasher_gadget")));
}

template<typename FieldT, typename HashT>
void COMM_gadget<FieldT, HashT>::generate_r1cs_constraints()
{
    // ensure_output_bitness set to true
    hasher->generate_r1cs_constraints(true);
}

template<typename FieldT, typename HashT>
void COMM_gadget<FieldT, HashT>::generate_r1cs_witness()
{
    hasher->generate_r1cs_witness();
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get128bits(
    libsnark::pb_variable_array<FieldT> &inner_k)
{
    libsnark::pb_variable_array<FieldT> ret;

    // Should always be satisfied
    // Sanity check to avoid going out of bound
    // in the for loop below
    assert(inner_k.size() > 128);

    for (int i = 0; i < 128; i++) {
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
    const libsnark::pb_variable<FieldT> &ZERO,
    libsnark::pb_variable_array<FieldT> &value_v)
{
    libsnark::pb_variable_array<FieldT> right_side;

    // Prepend the value with 192 '0' bits
    for (int i = 0; i < 192; i++) {
        right_side.emplace_back(ZERO);
    }

    for (size_t i = 0; i < value_v.size(); ++i) {
        right_side.emplace_back(value_v[i]);
    }

    // Check that we correctly built a 256-bit string
    assert(right_side.size() == 256);

    return right_side;
}

// See Zerocash extended paper, page 22
// The commitment cm is computed as
// HashT(HashT( trap_r || [HashT(a_pk, rho)]_[128]) || "0"*192 || v)
// We denote by trap_r the trapdoor r
template<typename FieldT, typename HashT>
COMM_cm_gadget<FieldT, HashT>::COMM_cm_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &ZERO,
    libsnark::pb_variable_array<FieldT> &a_pk,
    libsnark::pb_variable_array<FieldT> &rho,
    libsnark::pb_variable_array<FieldT> &trap_r,
    libsnark::pb_variable_array<FieldT> &value_v,
    libsnark::pb_variable<FieldT> result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
{
    // Allocate temporary results
    inner_k.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), FMT(this->annotation_prefix, " inner_k")));

    outer_k.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), FMT(this->annotation_prefix, " outer_k")));

    final_k.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), FMT(this->annotation_prefix, " final_k")));

    // Allocate gadgets
    inner_com_gadget.reset(new COMM_gadget<FieldT, HashT>(
        pb, a_pk, rho, inner_k, annotation_prefix));

    outer_com_gadget.reset(new COMM_gadget<FieldT, HashT>(
        pb, trap_r, get128bits(inner_k->bits), outer_k, annotation_prefix));

    final_com_gadget.reset(new COMM_gadget<FieldT, HashT>(
        pb,
        outer_k->bits,
        getRightSideCMCOMM(ZERO, value_v),
        final_k,
        annotation_prefix));

    // This gadget cast the `final_k` from bits to field element
    // We reverse the order otherwise the resulting linear combination is built
    // by interpreting our bit string as little endian.
    bits_to_field.reset(new libsnark::packing_gadget<FieldT>(
        pb,
        libsnark::pb_variable_array<FieldT>(
            final_k->bits.rbegin(), final_k->bits.rend()),
        result,
        FMT(this->annotation_prefix, " cm_bits_to_field")));
}

template<typename FieldT, typename HashT>
void COMM_cm_gadget<FieldT, HashT>::generate_r1cs_constraints()
{
    inner_com_gadget->generate_r1cs_constraints();
    outer_com_gadget->generate_r1cs_constraints();
    final_com_gadget->generate_r1cs_constraints();

    // Flag set to true, to check booleaness of `final_k`
    bits_to_field->generate_r1cs_constraints(true);
}

template<typename FieldT, typename HashT>
void COMM_cm_gadget<FieldT, HashT>::generate_r1cs_witness()
{
    inner_com_gadget->generate_r1cs_witness();
    outer_com_gadget->generate_r1cs_witness();
    final_com_gadget->generate_r1cs_witness();

    bits_to_field->generate_r1cs_witness_from_bits();
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_COMMITMENT_TCC__