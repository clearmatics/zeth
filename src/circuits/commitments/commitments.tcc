#ifndef __ZETH_COMMITMENT_CIRCUITS_TCC__
#define __ZETH_COMMITMENT_CIRCUITS_TCC__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/commitment.tcc

namespace libzeth {

template<typename FieldT>
libsnark::pb_variable<FieldT> get_var(libsnark::protoboard<FieldT>& pb, const std::string &annotation) {
    libsnark::pb_variable<FieldT> var;
    var.allocate(pb, annotation);
    return var;
}

template<typename FieldT>
libsnark::pb_variable<FieldT> get_iv(libsnark::protoboard<FieldT>& pb) {
    libsnark::pb_variable<FieldT> iv;
    iv.allocate(pb, "iv");
    pb.val(iv) = FieldT("14220067918847996031108144435763672811050758065945364308986253046354060608451");
    return iv;
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
) : MiMC_hash_gadget<FieldT>(pb, {a_pk, rho}, get_iv(pb), annotation_prefix)
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
                                                libsnark::pb_variable<FieldT>& r_trap,
                                                libsnark::pb_variable<FieldT>& r_mask,
                                                libsnark::pb_variable<FieldT>& masked,
                                                libsnark::pb_variable<FieldT>& k_inner,
                                                const std::string &annotation_prefix
) :
  libsnark::gadget<FieldT>(pb, annotation_prefix),
  r_mask(r_mask),
  k_inner(k_inner),
  masked(masked),
  hasher(pb, {r_trap, masked}, get_iv(pb), annotation_prefix)
{
}

template<typename FieldT>
void COMM_outer_k_gadget<FieldT>::generate_r1cs_constraints (){
        // Adding constraint for the Miyaguchi-Preneel equation
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
              r_mask + k_inner, 1,
              masked),
            ".masked = r_mask + inner_k");

        this->hasher.generate_r1cs_constraints();
    }


template<typename FieldT>
void COMM_outer_k_gadget<FieldT>::generate_r1cs_witness (){

      this->pb.val( this->masked ) = this->pb.val(r_mask) + this->pb.val(k_inner);
      this->hasher.generate_r1cs_witness();

    }

template<typename FieldT>
const libsnark::pb_variable<FieldT>& COMM_outer_k_gadget<FieldT>::result() const {
    return this->hasher.result();
  }

// cm = sha256(outer_k || 0^192 || value_v)
template<typename FieldT>
COMM_cm_gadget<FieldT>::COMM_cm_gadget(libsnark::protoboard<FieldT>& pb,
                                    libsnark::pb_variable<FieldT>& outer_k,
                                    libsnark::pb_variable<FieldT>& value_v, // 64 bits before, TODO perhaps constrain to 2^64
                                    const std::string &annotation_prefix
) : MiMC_hash_gadget<FieldT>(pb, {outer_k, value_v}, get_iv(pb), annotation_prefix)
{
    // Nothing
}


} // libzeth

#endif // __ZETH_COMMITMENT_CIRCUITS_TCC__
