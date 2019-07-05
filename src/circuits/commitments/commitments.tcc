#ifndef __ZETH_COMMITMENT_CIRCUITS_TCC__
#define __ZETH_COMMITMENT_CIRCUITS_TCC__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/commitment.tcc

namespace libzeth {

template<typename FieldT>
cm_gadget<FieldT>::cm_gadget(libsnark::protoboard<FieldT>& pb,
                        libsnark::pb_variable<FieldT>& a_pk,
                        libsnark::pb_variable<FieldT>& rho,
                        libsnark::pb_variable<FieldT>& r_trap,
                        libsnark::pb_variable<FieldT>& value,
                        const std::string &annotation_prefix
) : MiMC_hash_gadget<FieldT>(pb, {a_pk, rho, value}, r_trap, "clearmatics_cm", annotation_prefix)
{
    //
}

} // libzeth

#endif // __ZETH_COMMITMENT_CIRCUITS_TCC__
