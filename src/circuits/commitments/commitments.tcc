#ifndef __ZETH_COMMITMENT_CIRCUITS_TCC__
#define __ZETH_COMMITMENT_CIRCUITS_TCC__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/commitment.tcc

namespace libzeth {

// Function returning allocated pb_variable iv = sha3("Clearmatics")
// TODO put in util file
template<typename FieldT>
libsnark::pb_variable<FieldT> get_iv(libsnark::protoboard<FieldT>& pb) {
    libsnark::pb_variable<FieldT> iv;
    iv.allocate(pb, "iv");
    pb.val(iv) = FieldT("14220067918847996031108144435763672811050758065945364308986253046354060608451");
    return iv;
}


template<typename FieldT>
cm_gadget<FieldT>::cm_gadget(libsnark::protoboard<FieldT>& pb,
                        libsnark::pb_variable<FieldT>& a_pk,
                        libsnark::pb_variable<FieldT>& rho,
                        libsnark::pb_variable<FieldT>& r_trap,
                        libsnark::pb_variable<FieldT>& r_mask,
                        libsnark::pb_variable<FieldT>& value,
                        const std::string &annotation_prefix
) : libsnark::gadget<FieldT>(pb, annotation_prefix),
    a_pk(a_pk),
    rho(rho),
    r_trap(r_trap),
    r_mask(r_mask),
    value(value)
{
    // We allocate here intermediary values
    masked.allocate(pb, "masked");
    k_outer.allocate(pb, "k outer");

    // We then allocate the hashers
    inner_hasher.reset( new MiMC_hash_gadget<FieldT>(pb, {a_pk, rho}, get_iv(pb), "inner commitment"));
    outer_hasher.reset( new MiMC_hash_gadget<FieldT>(pb, {r_trap, masked}, get_iv(pb), "outer commitment"));
    final_hasher.reset( new MiMC_hash_gadget<FieldT>(pb, {k_outer, value}, get_iv(pb), "final commitment"));
}

template<typename FieldT>
void cm_gadget<FieldT>::generate_r1cs_constraints (){

    // We ensure "k_inner" is constrained by the address a_pk and rho
    (*this->inner_hasher).generate_r1cs_constraints();

    // We constrain masked by the computed k_inner and the trapdoor r_mask
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(
        r_mask + (*this->inner_hasher).result(), 1,
        masked),
       ".masked = r_mask + inner_k");

    // We ensure k is constrained by the tradoor r_trap and the masked inner commitment masked
    (*this->outer_hasher).generate_r1cs_constraints();

    // We finally ensure that the commitment cm is constrained by
    // the outer commitment k_outer and the value
    (*this->final_hasher).generate_r1cs_constraints();

    }

template<typename FieldT>
void cm_gadget<FieldT>::generate_r1cs_witness (){

    // We compute the the inner commitment k_inner
    (*this->inner_hasher).generate_r1cs_witness();

    // We retrieve the inner commitment value, compute the the masked inner commitment value
    // and fill its associated protoboard variable before computing the outer commitment
    FieldT k_inner = this->pb.val( (*this->inner_hasher).result() );
    this->pb.val( this->masked ) = this->pb.val(r_mask) + k_inner;
    (*this->outer_hasher).generate_r1cs_witness();

    // We retrieve the outer commitment value and fill its associated protoboard value
    this->pb.val( this->k_outer ) = this->pb.val( (*this->outer_hasher).result() );
    (*this->final_hasher).generate_r1cs_witness();

    }

template<typename FieldT>
const libsnark::pb_variable<FieldT> cm_gadget<FieldT>::result() const {
    return (*this->final_hasher).result();
  }

template<typename FieldT>
const libsnark::pb_variable<FieldT> cm_gadget<FieldT>::get_k() const {
    return this->k_outer;
  }

} // libzeth

#endif // __ZETH_COMMITMENT_CIRCUITS_TCC__
