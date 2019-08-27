#ifndef __ZETH_PRFS_CIRCUITS_TCC__
#define __ZETH_PRFS_CIRCUITS_TCC__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/prfs.tcc

namespace libzeth {

template<typename FieldT, typename HashT>
PRF_gadget<FieldT, HashT>::PRF_gadget(
    libsnark::protoboard<FieldT>& pb,
    libsnark::pb_variable_array<FieldT> x,
    libsnark::pb_variable_array<FieldT> y,
    std::shared_ptr<libsnark::digest_variable<FieldT>> result,
    const std::string &annotation_prefix
) :
    libsnark::gadget<FieldT>(pb, annotation_prefix), result(result)
{
    block.reset(new libsnark::block_variable<FieldT>(
        pb,
        {x, y},
        FMT(this->annotation_prefix, " block"))
    );

    hasher.reset(new HashT(
        pb,
        *block,
        *result,
        FMT(this->annotation_prefix, " hasher_gadget"))
    );
}

template<typename FieldT, typename HashT>
void PRF_gadget<FieldT, HashT>::generate_r1cs_constraints() {
    hasher->generate_r1cs_constraints(true);
}

template<typename FieldT, typename HashT>
void PRF_gadget<FieldT, HashT>::generate_r1cs_witness() {
    hasher->generate_r1cs_witness();
}

template<typename FieldT, typename HashT>
libsnark::pb_variable_array<FieldT> gen_256_zeroes(libsnark::pb_variable<FieldT>& ZERO) {
    libsnark::pb_variable_array<FieldT> ret;
    // We generate half a block of zeroes
    while (ret.size() < HashT::get_block_len() / 2) {
        ret.emplace_back(ZERO);
    }

    // Check that we correctly built a 256-bit (half a block) string since we use sha256
    assert(ret.size() == 256);

    return ret;
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_addr(
    libsnark::pb_variable<FieldT>& ZERO,
    libsnark::pb_variable_array<FieldT>& a_sk
) {
    libsnark::pb_variable_array<FieldT> tagged_a_sk;
    tagged_a_sk.emplace_back(ONE); // 1
    tagged_a_sk.emplace_back(ONE); // 11
    tagged_a_sk.emplace_back(ZERO); // 110
    tagged_a_sk.emplace_back(ZERO); // 1100

    // Should always be satisfied because a_sk
    // is a 256 bit string. This is just a sanity check
    // to make sure that the for loop doesn't
    // go out of the bound of the a_sk vector
    assert(a_sk.size() > 252);
    for (size_t i = 0; i < 252; ++i) {
        tagged_a_sk.emplace_back(a_sk[i]);
    }

    // Check that we correctly built a 256-bit string
    assert(tagged_a_sk.size() == 256);

    return tagged_a_sk;
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_nf(
    libsnark::pb_variable<FieldT>& ZERO,
    libsnark::pb_variable_array<FieldT>& a_sk
) {
    libsnark::pb_variable_array<FieldT> tagged_a_sk;
    tagged_a_sk.emplace_back(ONE); // 1
    tagged_a_sk.emplace_back(ONE); // 11
    tagged_a_sk.emplace_back(ONE); // 111
    tagged_a_sk.emplace_back(ZERO); // 1110

    // Should always be satisfied because a_sk
    // is a 256 bit string. This is just a sanity check
    // to make sure that the for loop doesn't
    // go out of the bound of the a_sk vector
    assert(a_sk.size() > 252);
    for (size_t i = 0; i < 252; ++i) {
        tagged_a_sk.emplace_back(a_sk[i]);
    }

    // Check that we correctly built a 256-bit string
    assert(tagged_a_sk.size() == 256);

    return tagged_a_sk;
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_pk(
    libsnark::pb_variable<FieldT>& ZERO,
    libsnark::pb_variable_array<FieldT>& a_sk,
    size_t index
) {
    libsnark::pb_variable_array<FieldT> tagged_a_sk;
    tagged_a_sk.emplace_back(ZERO); // 0

    // Index should either be 0 or 1 since we support
    // joinsplit with 2 inputs only
    if (index == 0) { // 0 || index
        tagged_a_sk.emplace_back(ZERO); // 00
    } else {
        tagged_a_sk.emplace_back(ONE); // 01
    }

    tagged_a_sk.emplace_back(ZERO); // 0 || index || 0
    tagged_a_sk.emplace_back(ZERO); // 0 || index || 00

    // Should always be satisfied because a_sk
    // is a 256 bit string. This is just a sanity check
    // to make sure that the for loop doesn't
    // go out of the bound of the a_sk vector
    assert(a_sk.size() > 252);
    for (size_t i = 0; i < 252; ++i) {
        tagged_a_sk.emplace_back(a_sk[i]);
    }

    // Check that we correctly built a 256-bit string
    assert(tagged_a_sk.size() == 256);

    return tagged_a_sk;
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_rho(
    libsnark::pb_variable<FieldT>& ZERO,
    libsnark::pb_variable_array<FieldT>& phi,
    size_t index
) {
    libsnark::pb_variable_array<FieldT> tagged_phi;
    tagged_phi.emplace_back(ZERO); // 0

    if (index == 0) { // 0 || index
        tagged_phi.emplace_back(ZERO); // 00
    } else {
        tagged_phi.emplace_back(ONE); // 01
    }

    tagged_phi.emplace_back(ONE); // 0 || index || 1
    tagged_phi.emplace_back(ZERO); // 0 || index || 10

    // Should always be satisfied because phi
    // is a 256 bit string. This is just a sanity check
    // to make sure that the for loop doesn't
    // go out of the bound of the phi vector
    assert(phi.size() > 252);
    for (size_t i = 0; i < 252; ++i) {
        tagged_phi.emplace_back(phi[i]);
    }

    // Check that we correctly built a 256-bit string
    assert(tagged_phi.size() == 256);

    return tagged_phi;
}

// PRF to generate the public addresses
// a_pk = sha256(1100 || [a_sk]_252 || 0^256): See ZCash protocol specification paper, page 57
template<typename FieldT, typename HashT>
PRF_addr_a_pk_gadget<FieldT, HashT>::PRF_addr_a_pk_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        libsnark::pb_variable_array<FieldT>& a_sk,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
        const std::string &annotation_prefix
) :
    PRF_gadget<FieldT, HashT>(pb, get_tag_addr(ZERO, a_sk), gen_256_zeroes<FieldT, HashT>(ZERO), result, annotation_prefix)
{
    // Nothing
}

// PRF to generate the nullifier
// nf = sha256(1110 || [a_sk]_252 || rho): See ZCash protocol specification paper, page 57
template<typename FieldT, typename HashT>
PRF_nf_gadget<FieldT, HashT>::PRF_nf_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        libsnark::pb_variable_array<FieldT>& a_sk,
        libsnark::pb_variable_array<FieldT>& rho,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
        const std::string &annotation_prefix
) :
    PRF_gadget<FieldT, HashT>(pb, get_tag_nf(ZERO, a_sk), rho, result, annotation_prefix)
{
    // Nothing
}


// PRF to generate the h_i
// h_i = sha256(0 || i || 00 || [a_sk]_252 || h_sig): See ZCash protocol specification paper, page 57
template<typename FieldT, typename HashT>
PRF_pk_gadget<FieldT, HashT>::PRF_pk_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        libsnark::pb_variable_array<FieldT>& a_sk,
        libsnark::pb_variable_array<FieldT>& h_sig,
        size_t index,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
        const std::string &annotation_prefix
) :
    PRF_gadget<FieldT, HashT>(pb, get_tag_pk(ZERO, a_sk, index), h_sig, result, annotation_prefix)
{
    // Nothing
}

// PRF to generate rho
// rho_i = sha256(0 || i || 10 || [a_sk]_252 || h_sig): See ZCash protocol specification paper, page 57
template<typename FieldT, typename HashT>
PRF_rho_gadget<FieldT, HashT>::PRF_rho_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        libsnark::pb_variable_array<FieldT>& phi,
        libsnark::pb_variable_array<FieldT>& h_sig,
        size_t index,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
        const std::string &annotation_prefix
) :
    PRF_gadget<FieldT, HashT>(pb, get_tag_rho(ZERO, phi, index), h_sig, result, annotation_prefix)
{
    // Nothing
}

} // libzeth

#endif // __ZETH_PRFS_CIRCUITS_TCC__
