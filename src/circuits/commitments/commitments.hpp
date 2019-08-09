#ifndef __ZETH_COMMITMENT_CIRCUITS_HPP__
#define __ZETH_COMMITMENT_CIRCUITS_HPP__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/commitment.tcc

#include <libsnark/gadgetlib1/gadget.hpp>
#include "circuits/sha256/sha256_ethereum.hpp"

namespace libzeth {

template<typename FieldT, typename HashT>
class COMM_gadget : libsnark::gadget<FieldT> {
private:
    std::shared_ptr<libsnark::block_variable<FieldT>> block;
    std::shared_ptr<HashT> hasher; // Hash gadget used as a commitment
    std::shared_ptr<libsnark::digest_variable<FieldT>> result;

public:
    COMM_gadget(libsnark::protoboard<FieldT>& pb,
                libsnark::pb_variable_array<FieldT> x,
                libsnark::pb_variable_array<FieldT> y,
                std::shared_ptr<libsnark::digest_variable<FieldT>> result, // sha256(x || y)
                const std::string &annotation_prefix = "COMM_gadget");
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get128bits(libsnark::pb_variable_array<FieldT>& inner_k);

// As mentioned in Zerocash extended paper, page 22
// Right side of the hash inputs to generate cm is: 0^192 || value_v (64 bits)
template<typename FieldT>
libsnark::pb_variable_array<FieldT> getRightSideCMCOMM(
    libsnark::pb_variable<FieldT>& ZERO,
    libsnark::pb_variable_array<FieldT>& value_v
);

// TODO: Implement the COMM_k_gadget as a 2 hash rounds in order to directly get the
// value of the commitment_k without needing 2 distinct gadgets for this.
//
// See Zerocash extended paper, page 22
// The commitment k is computed as k = sha256(r || [sha256(a_pk || rho)]_128)
// where we define the left part: inner_k = sha256(a_pk || rho)
// as being the inner commitment of k
template<typename FieldT, typename HashT>
class COMM_inner_k_gadget : public COMM_gadget<FieldT, HashT> {
public:
    COMM_inner_k_gadget(libsnark::protoboard<FieldT>& pb,
                        libsnark::pb_variable_array<FieldT>& a_pk,  // public address key, 256 bits
                        libsnark::pb_variable_array<FieldT>& rho,   // 256 bits
                        std::shared_ptr<libsnark::digest_variable<FieldT>> result, // sha256(a_pk || rho)
                        const std::string &annotation_prefix = "COMM_inner_k_gadget");
};

// See Zerocash extended paper, page 22
// The commitment k is computed as k = sha256(r || [sha256(a_pk || rho)]_128)
// where we define: outer_k = sha256(r || [inner_commitment]_128)
// as being the outer commitment of k
// We denote by trap_r the trapdoor r
template<typename FieldT, typename HashT>
class COMM_outer_k_gadget : public COMM_gadget<FieldT, HashT> {
public:
    COMM_outer_k_gadget(libsnark::protoboard<FieldT>& pb,
                        libsnark::pb_variable_array<FieldT>& trap_r,    // 384 bits
                        libsnark::pb_variable_array<FieldT>& inner_k,   // 256 bits, but we only keep 128 bits out of it
                        std::shared_ptr<libsnark::digest_variable<FieldT>> result,  // sha256(trap_r || [inner_k]_128)
                        const std::string &annotation_prefix = "COMM_outer_k_gadget");
};

// cm = sha256(outer_k || 0^192 || value_v)
template<typename FieldT, typename HashT>
class COMM_cm_gadget : public COMM_gadget<FieldT, HashT> {
public:
    COMM_cm_gadget(libsnark::protoboard<FieldT>& pb,
                   libsnark::pb_variable<FieldT>& ZERO,
                   libsnark::pb_variable_array<FieldT>& outer_k,   // 256 bits
                   libsnark::pb_variable_array<FieldT>& value_v,   //  64 bits
                   std::shared_ptr<libsnark::digest_variable<FieldT>> result,  // sha256(outer_k || 0^192 || value_v)
                   const std::string &annotation_prefix = "COMM_cm_gadget");
};

} // libzeth
#include "circuits/commitments/commitments.tcc"

#endif // __ZETH_COMMITMENT_CIRCUITS_HPP__
