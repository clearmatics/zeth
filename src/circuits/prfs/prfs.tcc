#ifndef __ZETH_PRFS_CIRCUITS_TCC__
#define __ZETH_PRFS_CIRCUITS_TCC__

// DISCLAIMER: 
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/prfs.tcc

namespace libzeth {

template<typename FieldT>
PRF_gadget<FieldT>::PRF_gadget(libsnark::protoboard<FieldT>& pb,
                               libsnark::pb_variable<FieldT>& /* ZERO */,
                               libsnark::pb_variable_array<FieldT> x,
                               libsnark::pb_variable_array<FieldT> y,
                               std::shared_ptr<libsnark::digest_variable<FieldT>> result,
                               const std::string &annotation_prefix) :
    libsnark::gadget<FieldT>(pb, annotation_prefix), result(result)
{

    block.reset(new libsnark::block_variable<FieldT>(pb, {
        x,
        y
    }, "PRF_block"));

    hasher.reset(new sha256_ethereum<FieldT>(
        pb,
        libsnark::SHA256_block_size,
        *block,
        *result,
        "PRF_ethereum_hasher")
    );
}

template<typename FieldT>
void PRF_gadget<FieldT>::generate_r1cs_constraints() {
    hasher->generate_r1cs_constraints(true);
}

template<typename FieldT>
void PRF_gadget<FieldT>::generate_r1cs_witness() {
    hasher->generate_r1cs_witness();
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> gen256zeroes(libsnark::pb_variable<FieldT>& ZERO) {
    libsnark::pb_variable_array<FieldT> ret;
    while (ret.size() < 256) {
        ret.emplace_back(ZERO);
    }

    // Dummy assert that double check 
    // that we correctly built a 256-bit string
    assert(ret.size() == 256);

    return ret;
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> getRightSideNFPRF(
    libsnark::pb_variable<FieldT>& ZERO,
    libsnark::pb_variable_array<FieldT>& rho
) {
    libsnark::pb_variable_array<FieldT> right_side;
    right_side.emplace_back(ZERO); // 0
    right_side.emplace_back(ONE); // 01

    // Should always be satisfied because rho
    // is a 256 bit string. This is just a sanity check
    // to make sure that the for loop doesn't
    // go out of the bound of the rho vector
    assert(rho.size() > 254);

    for (size_t i = 0; i < 254; ++i)
    {
        right_side.emplace_back(rho[i]);
    }

    // Check that we correctly built a 256-bit string
    assert(right_side.size() == 256);

    return right_side;
}

// a_pk = sha256(a_sk || 0^256): See Zerocash extended paper, page 22, 
// paragraph "Instantiating the NP statement POUR"
template<typename FieldT>
PRF_addr_a_pk_gadget<FieldT>::PRF_addr_a_pk_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        libsnark::pb_variable_array<FieldT>& a_sk,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
        const std::string &annotation_prefix) : 
    PRF_gadget<FieldT>(pb, ZERO, a_sk, gen256zeroes(ZERO), result, annotation_prefix)
{
    // Nothing 
}

// PRF to generate the nullifier
// nf = sha256(a_sk || 01 || [rho]_254): See Zerocash extended paper, page 22
template<typename FieldT>
PRF_nf_gadget<FieldT>::PRF_nf_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        libsnark::pb_variable_array<FieldT>& a_sk,
        libsnark::pb_variable_array<FieldT>& rho,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
        const std::string &annotation_prefix) : 
    PRF_gadget<FieldT>(pb, ZERO, a_sk, getRightSideNFPRF(ZERO, rho), result, annotation_prefix)
{
    // Nothing
}

} // libzeth

#endif // __ZETH_PRFS_CIRCUITS_TCC__