#ifndef __ZETH_COMMITMENT_CIRCUITS_TCC__
#define __ZETH_COMMITMENT_CIRCUITS_TCC__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/commitment.tcc

namespace libzeth {

template<typename FieldT>
COMM_gadget<FieldT>::COMM_gadget(libsnark::protoboard<FieldT>& pb,
                                libsnark::pb_variable<FieldT> x,
                                libsnark::pb_variable<FieldT> y,
                                const std::string &annotation_prefix
) : libsnark::gadget<FieldT>(pb), result(result)
{

    libsnark::pb_variable iv;
    iv.allocate(pb, "iv var");//TODO to fix annotation iv="Clearmatics"
    pb.val(iv) = FieldT("14220067918847996031108144435763672811050758065945364308986253046354060608451");

    hash_gadget(pb, iv, {x, y}, annotation_prefix);

}


template<typename FieldT>
const libsnark::pb_variable<FieldT>& COMM_gadget<FieldT>::result() const {
    return hash_gadget.result();
  }

template<typename FieldT>
void COMM_gadget<FieldT>::generate_r1cs_constraints() {
    hash_gadget.generate_r1cs_constraints(); // ensure_output_bitness set to true
}

template<typename FieldT>
void COMM_gadget<FieldT>::generate_r1cs_witness() {
    hash_gadget.generate_r1cs_witness();
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
                                                libsnark::pb_variable<FieldT>& a_pk, // 256 bits
                                                libsnark::pb_variable<FieldT>& rho, // 256 bits
                                                const std::string &annotation_prefix
) : COMM_gadget<FieldT>(pb, ZERO, a_pk, rho, annotation_prefix)
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
                                                libsnark::pb_variable_array<FieldT>& trap_r, // 384 bits
                                                libsnark::pb_variable<FieldT>& inner_k, // 256 bits, but we only keep 128 bits our of it
                                                const std::string &annotation_prefix
) :
  assert(trap_r.size==2);
  COMM_gadget<FieldT>(pb, trap_r[0], trap_r[1]+inner_k, annotation_prefix)
{
    // Nothing
}

// cm = sha256(outer_k || 0^192 || value_v)
template<typename FieldT>
COMM_cm_gadget<FieldT>::COMM_cm_gadget(libsnark::protoboard<FieldT>& pb,
                                    libsnark::pb_variable<FieldT>& outer_k,
                                    libsnark::pb_variable<FieldT>& value_v, // 64 bits before, TODO perhaps constrain to 2^64
                                    const std::string &annotation_prefix
) : COMM_gadget<FieldT>(pb, outer_k, value_v, annotation_prefix)
{
    // Nothing
}

} // libzeth

#endif // __ZETH_COMMITMENT_CIRCUITS_TCC__
