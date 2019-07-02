#ifndef __ZETH_COMMITMENT_CIRCUITS_HPP__
#define __ZETH_COMMITMENT_CIRCUITS_HPP__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/commitment.tcc

#include <libsnark/gadgetlib1/gadget.hpp>
#include "circuits/mimc/mimc_hash.hpp"
#include "circuits/circuits-util.hpp"

namespace libzeth {


// For more details, see Zerocash extended paper, page 22:
// The commitment k is computed as k = sha256(r || [sha256(a_pk || rho)]_128)
// where we define the left part: inner_k = sha256(a_pk || rho) as being the inner commitment of k

// MiMC update: We decided to replace sha256 by mimc_hash to work everywhere in F_p.
// As mimc_hash is based on the mimc encryption function and the Miyagushi-Preneel construct,
// we need to set the hash iv as well as the encryption key. Furthermore, the inputs are now field elements.
// We decided to use the same IV (sha3("Clearmatics")), set in the .tcc, and encryption key (b"mimc"), set by default in mimc_hash.tcc.
// We decided to update from nested commitments to one commitment without []_128 operation 
// as suggested by ZCash in their protocol specification at chapter 8.5 Internal hash collision attack and fix
// We now have: cm = mimc_hash(a_pk, rho, r_trap, value)

template<typename FieldT>
class cm_gadget : public MiMC_hash_gadget<FieldT> {

public:
    cm_gadget(libsnark::protoboard<FieldT>& pb,
                        libsnark::pb_variable<FieldT>& a_pk,
                        libsnark::pb_variable<FieldT>& rho,
                        libsnark::pb_variable<FieldT>& r_trap,
                        libsnark::pb_variable<FieldT>& value,
                        const std::string &annotation_prefix = "cm_gadget");

};


} // libzeth
#include "circuits/commitments/commitments.tcc"

#endif // __ZETH_COMMITMENT_CIRCUITS_HPP__
