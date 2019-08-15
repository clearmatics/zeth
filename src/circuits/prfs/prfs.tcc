#ifndef __ZETH_PRFS_CIRCUITS_TCC__
#define __ZETH_PRFS_CIRCUITS_TCC__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/prfs.tcc

namespace libzeth {

template<typename FieldT, typename HashT>
PRF_gadget<FieldT, HashT>::PRF_gadget(libsnark::protoboard<FieldT>& pb,
                                      libsnark::pb_variable_array<FieldT> x,
                                      libsnark::pb_variable_array<FieldT> y,
                                      std::shared_ptr<libsnark::digest_variable<FieldT>> result,
                                      const std::string &annotation_prefix) :
    libsnark::gadget<FieldT>(pb, annotation_prefix), result(result)
{

    block.reset(new libsnark::block_variable<FieldT>(pb, {
            x,
            y
        }, FMT(this->annotation_prefix, " block"))
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
libsnark::pb_variable_array<FieldT> gen256zeroes(libsnark::pb_variable<FieldT>& ZERO) {
    libsnark::pb_variable_array<FieldT> ret;
    while (ret.size() < HashT::get_block_len()/2) { // We generate half a block of zeroes
        ret.emplace_back(ZERO);
    }

    // Check that we correctly built a 256-bit (half a block) string since we use sha256
    assert(ret.size() == 256);

    return ret;
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> getTagAddr(
    libsnark::pb_variable<FieldT>& ZERO,
    libsnark::pb_variable_array<FieldT>& x
) {
    libsnark::pb_variable_array<FieldT> tagged;
    tagged.emplace_back(ONE);   // 1
    tagged.emplace_back(ONE);   // 11
    tagged.emplace_back(ZERO);  // 110
    tagged.emplace_back(ZERO);  // 1100

    // Should always be satisfied because a_sk
    // is a 256 bit string. This is just a sanity check
    // to make sure that the for loop doesn't
    // go out of the bound of the a_sk vector
    assert(x.size() > 252);

    for (size_t i = 0; i < 252; ++i)
    {
        tagged.emplace_back(x[i]);
    }

    // Check that we correctly built a 256-bit string
    assert(tagged.size() == 256);

    return tagged;
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> getTagNf(
    libsnark::pb_variable<FieldT>& ZERO,
    libsnark::pb_variable_array<FieldT>& ask
) {
    libsnark::pb_variable_array<FieldT> tagged;
    tagged.emplace_back(ONE);   // 1
    tagged.emplace_back(ONE);   // 11
    tagged.emplace_back(ONE);   // 111
    tagged.emplace_back(ZERO);  // 1110

    // Should always be satisfied because a_sk
    // is a 256 bit string. This is just a sanity check
    // to make sure that the for loop doesn't
    // go out of the bound of the a_sk vector
    assert(ask.size() > 254);

    for (size_t i = 0; i < 252; ++i)
    {
        tagged.emplace_back(ask[i]);
    }

    // Check that we correctly built a 256-bit string
    assert(tagged.size() == 256);

    return tagged;
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> getTagPk(
    libsnark::pb_variable<FieldT>& ZERO,
    libsnark::pb_variable_array<FieldT>& ask,
    size_t index
) {
    libsnark::pb_variable_array<FieldT> tagged;
    tagged.emplace_back(ZERO);      // 0
    if (index == 0)
    {
        tagged.emplace_back(ZERO);  // 00
    } else {
        tagged.emplace_back(ONE);   // 01
    }
    tagged.emplace_back(ZERO);      // 0i0
    tagged.emplace_back(ZERO);      // 0i00

    // Should always be satisfied because a_sk
    // is a 256 bit string. This is just a sanity check
    // to make sure that the for loop doesn't
    // go out of the bound of the a_sk vector
    assert(ask.size() > 254);

    for (size_t i = 0; i < 252; ++i)
    {
        tagged.emplace_back(ask[i]);
    }

    // Check that we correctly built a 256-bit string
    assert(tagged.size() == 256);

    return tagged;
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> getTagRho(
    libsnark::pb_variable<FieldT>& ZERO,
    libsnark::pb_variable_array<FieldT>& phi,
    size_t index
) {
    libsnark::pb_variable_array<FieldT> tagged;
    tagged.emplace_back(ZERO);      // 0
    if (index == 0)
    {
        tagged.emplace_back(ZERO);  // 00
    } else {
        tagged.emplace_back(ONE);   // 01
    }
    tagged.emplace_back(ONE);      // 0i1
    tagged.emplace_back(ZERO);      // 0i10

    // Should always be satisfied because phi
    // is a 256 bit string. This is just a sanity check
    // to make sure that the for loop doesn't
    // go out of the bound of the phi vector
    assert(phi.size() > 254);

    for (size_t i = 0; i < 252; ++i)
    {
        tagged.emplace_back(phi[i]);
    }

    // Check that we correctly built a 256-bit string
    assert(tagged.size() == 256);

    return tagged;
}

// PRF to generate the public addresses
// a_pk = sha256(1100 || [a_sk]_252 || 0^256): See ZCash protocol specification paper, page 57
template<typename FieldT, typename HashT>
PRF_addr_a_pk_gadget<FieldT, HashT>::PRF_addr_a_pk_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        libsnark::pb_variable_array<FieldT>& a_sk,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
        const std::string &annotation_prefix) :
    PRF_gadget<FieldT, HashT>(pb, getTagAddr(ZERO, a_sk), gen256zeroes<FieldT, HashT>(ZERO), result, annotation_prefix)
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
        const std::string &annotation_prefix) :
    PRF_gadget<FieldT, HashT>(pb, getTagNf(ZERO, a_sk), rho, result, annotation_prefix)
{
    // Nothing
}


// PRF to generate the h_i
// h_i = sha256(0 || index || 00 || [a_sk]_252 || h_sig): See ZCash protocol specification paper, page 57
template<typename FieldT, typename HashT>
PRF_pk_gadget<FieldT, HashT>::PRF_pk_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        libsnark::pb_variable_array<FieldT>& a_sk,
        libsnark::pb_variable_array<FieldT>& h_sig,
        size_t index,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
        const std::string &annotation_prefix) :
    PRF_gadget<FieldT, HashT>(pb, getTagPk(ZERO, a_sk, index), h_sig, result, annotation_prefix)
{
    // Nothing
}

// PRF to generate rho
// rho_i = sha256(0 || index || 10 || [a_sk]_252 || h_sig): See ZCash protocol specification paper, page 57
template<typename FieldT, typename HashT>
PRF_rho_gadget<FieldT, HashT>::PRF_rho_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        libsnark::pb_variable_array<FieldT>& phi,
        libsnark::pb_variable_array<FieldT>& h_sig,
        size_t index,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
        const std::string &annotation_prefix) :
    PRF_gadget<FieldT, HashT>(pb, getTagRho(ZERO, phi, index), h_sig, result, annotation_prefix)
{
    // Nothing
}

} // libzeth

#endif // __ZETH_PRFS_CIRCUITS_TCC__
