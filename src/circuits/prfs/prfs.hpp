#ifndef __ZETH_PRFS_CIRCUITS_HPP__
#define __ZETH_PRFS_CIRCUITS_HPP__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/prfs.tcc

#include <libsnark/gadgetlib1/gadget.hpp>

#include "circuits/sha256/sha256_ethereum.hpp"

namespace libzeth {

template<typename FieldT, typename HashT>
class PRF_gadget : public libsnark::gadget<FieldT> {
private:
    std::shared_ptr<libsnark::block_variable<FieldT>> block;
    std::shared_ptr<HashT> hasher;
    std::shared_ptr<libsnark::digest_variable<FieldT>> result;

public:
    PRF_gadget(libsnark::protoboard<FieldT>& pb,
               libsnark::pb_variable_array<FieldT> x,
               libsnark::pb_variable_array<FieldT> y,
               std::shared_ptr<libsnark::digest_variable<FieldT>> result, // sha256(x || y)
               const std::string &annotation_prefix = " base_PRF_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

// This function is useful as the generation of a_pk is done via a_pk = sha256(a_sk || 0^256)
// See Zerocash extended paper, page 22, paragraph "Instantiating the NP statement POUR"
template<typename FieldT, typename HashT> libsnark::pb_variable_array<FieldT> gen256zeroes(libsnark::pb_variable<FieldT>& ZERO);

// As mentioned in Zerocash extended paper, page 22, the left side of the PRF that computes the nf, is equal to
// 01 || [rho]_254. This function takes rho, keep only 254 bits form it and preprend '01' to the result
template<typename FieldT, typename HashT> libsnark::pb_variable_array<FieldT> getRightSideNFPRF(
    libsnark::pb_variable<FieldT>& ZERO,
    libsnark::pb_variable_array<FieldT>& rho
);

// a_pk = sha256(a_sk || 0^256): See Zerocash extended paper, page 22,
// paragraph "Instantiating the NP statement POUR"
template<typename FieldT, typename HashT>
class PRF_addr_a_pk_gadget : public PRF_gadget<FieldT, HashT> {
public:
    PRF_addr_a_pk_gadget(libsnark::protoboard<FieldT>& pb,
                        libsnark::pb_variable<FieldT>& ZERO,
                        libsnark::pb_variable_array<FieldT>& a_sk,
                        std::shared_ptr<libsnark::digest_variable<FieldT>> result,  // sha256(a_sk || 0^256)
                        const std::string &annotation_prefix = " a_pk_PRF_gadget");
};

// PRF to generate the nullifier
// nf = sha256(a_sk || 01 || [rho]_254): See Zerocash extended paper, page 22
template<typename FieldT, typename HashT>
class PRF_nf_gadget : public PRF_gadget<FieldT, HashT> {
public:
    PRF_nf_gadget(libsnark::protoboard<FieldT>& pb,
                libsnark::pb_variable<FieldT>& ZERO,
                libsnark::pb_variable_array<FieldT>& a_sk,
                libsnark::pb_variable_array<FieldT>& rho,
                std::shared_ptr<libsnark::digest_variable<FieldT>> result, // sha256(a_sk || 01 || [rho]_254)
                const std::string &annotation_prefix = " nf_PRF_gadget");
};

} // libzeth
#include "circuits/prfs/prfs.tcc"

#endif // __ZETH_PRFS_CIRCUITS_HPP__
