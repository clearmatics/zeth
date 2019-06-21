#ifndef __ZETH_COMMITMENT_CIRCUITS_HPP__
#define __ZETH_COMMITMENT_CIRCUITS_HPP__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/commitment.tcc

#include <libsnark/gadgetlib1/gadget.hpp>
#include "circuits/mimc/mimc_hash.hpp"

namespace libzeth {

// TODO: Implement the COMM_k_gadget as a 2 hash rounds in order to directly get the
// value of the commitment_k without needing 2 distinct gadgets for this.
//
// See Zerocash extended paper, page 22
// The commitment k is computed as k = sha256(r || [sha256(a_pk || rho)]_128)
// where we define the left part: inner_k = sha256(a_pk || rho)
// as being the inner commitment of k
template<typename FieldT>
class COMM_gadget : public MiMC_hash_gadget<FieldT> {
public:
    COMM_gadget(libsnark::protoboard<FieldT>& pb,
                        libsnark::pb_variable<FieldT>& left,
                        libsnark::pb_variable<FieldT>& right,
                        const std::string &annotation_prefix = "COMM_gadget");
};

// See Zerocash extended paper, page 22
// The commitment k is computed as k = sha256(r || [sha256(a_pk || rho)]_128)
// where we define: outer_k = sha256(r || [inner_commitment]_128)
// as being the outer commitment of k
// We denote by trap_r the trapdoor r
template<typename FieldT>
class COMM_outer_k_gadget : public libsnark::gadget<FieldT> {
  MiMC_hash_gadget<FieldT> hasher;
  libsnark::pb_variable<FieldT> masked;
  libsnark::pb_variable<FieldT> r_mask;
  libsnark::pb_variable<FieldT> k_inner;

public:
    COMM_outer_k_gadget(libsnark::protoboard<FieldT>& pb,
                        libsnark::pb_variable<FieldT>& r_trap, // trap and mask
                        libsnark::pb_variable<FieldT>& r_mask, // trap and mask
                        libsnark::pb_variable<FieldT>& masked,
                        libsnark::pb_variable<FieldT>& k_inner,
                        const std::string &annotation_prefix = "COMM_outer_k_gadget");

    void generate_r1cs_constraints ();
	  void generate_r1cs_witness ();
    const  libsnark::pb_variable<FieldT> result() const;
};

} // libzeth
#include "circuits/commitments/commitments.tcc"

#endif // __ZETH_COMMITMENT_CIRCUITS_HPP__
