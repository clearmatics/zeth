#ifndef __ZETH_COMMITMENT_CIRCUITS_HPP__
#define __ZETH_COMMITMENT_CIRCUITS_HPP__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/commitment.tcc

#include <libsnark/gadgetlib1/gadget.hpp>
#include "circuits/mimc/mimc_hash.hpp"

namespace libzeth {

template<typename FieldT>
class COMM_gadget : libsnark::gadget<FieldT> {
  MiMC_Hash_gadget<FieldT> hash_gadget;

  public:
    COMM_gadget(libsnark::protoboard<FieldT>& pb,
                libsnark::pb_variable_array<FieldT> x,
                libsnark::pb_variable_array<FieldT> y,
                const std::string &annotation_prefix = "COMM_gadget");
    libsnark::pb_variable<FieldT>& result() const;
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

// TODO: Implement the COMM_k_gadget as a 2 hash rounds in order to directly get the
// value of the commitment_k without needing 2 distinct gadgets for this.
//
// See Zerocash extended paper, page 22
// The commitment k is computed as k = sha256(r || [sha256(a_pk || rho)]_128)
// where we define the left part: inner_k = sha256(a_pk || rho)
// as being the inner commitment of k
template<typename FieldT>
class COMM_inner_k_gadget : public COMM_gadget<FieldT> {
public:
    COMM_inner_k_gadget(libsnark::protoboard<FieldT>& pb,
                        libsnark::pb_variable<FieldT>& a_pk,
                        libsnark::pb_variable<FieldT>& rho,
                        const std::string &annotation_prefix = "COMM_inner_k_gadget");
};

// See Zerocash extended paper, page 22
// The commitment k is computed as k = sha256(r || [sha256(a_pk || rho)]_128)
// where we define: outer_k = sha256(r || [inner_commitment]_128)
// as being the outer commitment of k
// We denote by trap_r the trapdoor r
template<typename FieldT>
class COMM_outer_k_gadget : public COMM_gadget<FieldT> {
public:
    COMM_outer_k_gadget(libsnark::protoboard<FieldT>& pb,
                        libsnark::pb_variable_array<FieldT>& trap_r, // trap and mask
                        libsnark::pb_variable<FieldT>& inner_k,
                        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
                        const std::string &annotation_prefix = "COMM_outer_k_gadget");
};

template<typename FieldT>
class COMM_cm_gadget : public COMM_gadget<FieldT> {
public:
    COMM_cm_gadget(libsnark::protoboard<FieldT>& pb,
                libsnark::pb_variable<FieldT>& outer_k,
                libsnark::pb_variable<FieldT>& value_v, // 64 bits before, TODO we could constrain it
                std::shared_ptr<libsnark::pb_variable<FieldT>> result,
                const std::string &annotation_prefix = "COMM_cm_gadget");
};

} // libzeth
#include "circuits/commitments/commitments.tcc"

#endif // __ZETH_COMMITMENT_CIRCUITS_HPP__
