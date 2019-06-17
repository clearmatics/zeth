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
        const std::string &annotation_prefix) :
        libsnark::gadget(pb, annotation_prefix)
{
  libsnark::pb_variable zero_var, iv;

  zero_var.allocate(pb, "zero var");//TODO to fix annotation
  pb.val(zero_var) = 0;

  iv.allocate(pb, "iv var");//TODO to fix annotation
  pb.val(iv) = FieldT("7655352919458297598499032567765357605187604397960652899494713742188031353302");

  hash_gadget(pb, iv, {a_sk, zero_var}, annotation_prefix);
}


template<typename FieldT>
const libsnark::pb_variable<FieldT>& PRF_addr_a_pk_gadget<FieldT>::result() const {
    return hash_gadget.result();
}

template<typename FieldT>
void PRF_addr_a_pk_gadget<FieldT>::generate_r1cs_constraints() {
    hash_gadget.generate_r1cs_constraints(); // ensure_output_bitness set to true
}

template<typename FieldT>
void PRF_addr_a_pk_gadget<FieldT>::generate_r1cs_witness() {
    hash_gadget.generate_r1cs_witness();
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
        libsnark::gadget(pb, annotation_prefix)
{
  libsnark::pb_variable<FieldT> iv;

  iv.allocate(pb, "iv var");//TODO to fix annotation
  pb.val(iv) = FieldT("38594890471543702135425523844252992926779387339253565328142220201141984377400");

  hash_gadget(pb, iv, {a_sk, rho}, annotation_prefix);
}

template<typename FieldT>
const libsnark::pb_variable<FieldT>& PRF_nf_gadget<FieldT>::result() const {
    return hash_gadget.result();
}

template<typename FieldT>
void PRF_nf_gadget<FieldT>::generate_r1cs_constraints() {
    hash_gadget.generate_r1cs_constraints(); // ensure_output_bitness set to true
}

template<typename FieldT>
void PRF_nf_gadget<FieldT>::generate_r1cs_witness() {
    hash_gadget.generate_r1cs_witness();
}


#endif // __ZETH_PRFS_CIRCUITS_TCC__
