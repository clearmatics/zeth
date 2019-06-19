#ifndef __ZETH_PRFS_CIRCUITS_TCC__
#define __ZETH_PRFS_CIRCUITS_TCC__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/prfs.tcc

namespace libzeth {

//TODO add PRF parent class



template<typename FieldT>
libsnark::pb_variable<FieldT> get_zero(libsnark::protoboard<FieldT>& pb) {
    libsnark::pb_variable<FieldT> zero;
    zero.allocate(pb, "zero");
    pb.val(zero) = FieldT("0");
    return zero;
}

template<typename FieldT>
libsnark::pb_variable<FieldT> get_iv_add(libsnark::protoboard<FieldT>& pb) {
    libsnark::pb_variable<FieldT> iv;
    iv.allocate(pb, "iv_add");
    pb.val(iv) = FieldT("7655352919458297598499032567765357605187604397960652899494713742188031353302");
    return iv;
}


template<typename FieldT>
libsnark::pb_variable<FieldT> get_iv_sn(libsnark::protoboard<FieldT>& pb) {
    libsnark::pb_variable<FieldT> iv;
    iv.allocate(pb, "iv_sn");
    pb.val(iv) = FieldT("38594890471543702135425523844252992926779387339253565328142220201141984377400");
    return iv;
}


template<typename FieldT>
libsnark::pb_variable<FieldT> get_iv_pk(libsnark::protoboard<FieldT>& pb) {
    libsnark::pb_variable<FieldT> iv;
    iv.allocate(pb, "iv_pk");
    pb.val(iv) = FieldT("20715549373167656640519441333099474211916836972862576858009333815040496998894");
    return iv;
}


// a_pk = sha256(a_sk || 0^256): See Zerocash extended paper, page 22,
// paragraph "Instantiating the NP statement POUR"
// Generating public address addr from secret key a_sk
template<typename FieldT>
PRF_addr_a_pk_gadget<FieldT>::PRF_addr_a_pk_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& a_sk,
        const std::string &annotation_prefix
      ) :
      MiMC_hash_gadget<FieldT>(pb, {a_sk, get_zero(pb)}, get_iv_add(pb), annotation_prefix)
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
      MiMC_hash_gadget<FieldT>(pb, {a_sk, rho}, get_iv_sn(pb), annotation_prefix)
{
  //
}

} //libzeth

#endif // __ZETH_PRFS_CIRCUITS_TCC__
