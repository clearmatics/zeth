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

// See Zerocash extended paper, page 22
// The commitment cm is computed as
// HashT(HashT( trap_r || [HashT(a_pk, rho)]_[128]) || "0"*192 || v)
// We denote by trap_r the trapdoor r
template<typename FieldT, typename HashT>
COMM_cm_gadget<FieldT, HashT>::COMM_cm_gadget(
    libsnark::protoboard<FieldT> &pb,
    libsnark::pb_variable_array<FieldT> &a_pk,
    libsnark::pb_variable_array<FieldT> &rho,
    libsnark::pb_variable_array<FieldT> &trap_r,
    libsnark::pb_variable_array<FieldT> &value_v,
    libsnark::pb_variable<FieldT> result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , a_pk(a_pk)
    , rho(rho)
    , trap_r(trap_r)
    , value_v(value_v)
{
    // Allocate temporary variable
    input.allocate(
        pb,
        ZETH_V_SIZE + 2 * HashT::get_digest_len(),
        FMT(this->annotation_prefix, " cm_input"));

    temp_result.reset(new libsnark::digest_variable<FieldT>(
        pb,
        HashT::get_digest_len(),
        FMT(this->annotation_prefix, " cm_temp_output")));

    // Allocate gadgets
    com_gadget.reset(new COMM_gadget<FieldT, HashT>(
        pb, trap_r, input, temp_result, annotation_prefix));

    // This gadget cast the `temp_result` from bits to field element
    // We reverse the order otherwise the resulting linear combination is built
    // by interpreting our bit string as little endian.
    bits_to_field.reset(new libsnark::packing_gadget<FieldT>(
        pb,
        libsnark::pb_variable_array<FieldT>(
            temp_result->bits.rbegin(), temp_result->bits.rend()),
        result,
        FMT(this->annotation_prefix, " cm_bits_to_field")));
}

template<typename FieldT, typename HashT>
void COMM_cm_gadget<FieldT, HashT>::generate_r1cs_constraints()
{
    com_gadget->generate_r1cs_constraints();

    // Flag set to true, to check booleaness of `final_k`
    bits_to_field->generate_r1cs_constraints(true);
}

template<typename FieldT, typename HashT>
void COMM_cm_gadget<FieldT, HashT>::generate_r1cs_witness()
{
    std::vector<bool> temp;
    std::vector<bool> apk_bits = a_pk.get_bits(this->pb);
    temp.insert(temp.end(), apk_bits.begin(), apk_bits.end());
    std::vector<bool> rho_bits = rho.get_bits(this->pb);
    temp.insert(temp.end(), rho_bits.begin(), rho_bits.end());
    std::vector<bool> v_bits = value_v.get_bits(this->pb);
    temp.insert(temp.end(), v_bits.begin(), v_bits.end());
    input.fill_with_bits(this->pb, temp);

    com_gadget->generate_r1cs_witness();
    bits_to_field->generate_r1cs_witness_from_bits();
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_COMMITMENT_TCC__