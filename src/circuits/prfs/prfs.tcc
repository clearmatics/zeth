#ifndef __ZETH_PRFS_CIRCUITS_TCC__
#define __ZETH_PRFS_CIRCUITS_TCC__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/prfs.tcc

namespace libzeth {

//TODO add PRF parent class

// a_pk = sha256(a_sk || 0^256): See Zerocash extended paper, page 22,
// paragraph "Instantiating the NP statement POUR"
// Generating public address addr from secret key a_sk
template<typename FieldT>
PRF_addr_a_pk_gadget<FieldT>::PRF_addr_a_pk_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& a_sk,
        const std::string &annotation_prefix
      ) :
      MiMC_hash_gadget<FieldT>(pb, {get_var(pb, FieldT("0"), "zero_var")}, a_sk, "clearmatics_add", annotation_prefix)
{
  //
}

// PRF to generate the nullifier
// nf = sha256(a_sk || 01 || [rho]_254): See Zerocash extended paper, page 22
// TODO: add clarification
template<typename FieldT>
PRF_nf_gadget<FieldT>::PRF_nf_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& a_sk,
        libsnark::pb_variable<FieldT>& rho,
        const std::string &annotation_prefix) :
      MiMC_hash_gadget<FieldT>(pb, {rho}, a_sk, "clearmatics_sn", annotation_prefix)
{
  //
}

} //libzeth

#endif // __ZETH_PRFS_CIRCUITS_TCC__
