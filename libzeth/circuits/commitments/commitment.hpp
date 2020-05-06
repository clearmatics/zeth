#ifndef __ZETH_CIRCUITS_COMMITMENT_HPP__
#define __ZETH_CIRCUITS_COMMITMENT_HPP__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/commitment.tcc

#include "libzeth/zeth_constants.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>

namespace libzeth
{

template<typename FieldT, typename HashT>
class COMM_gadget : libsnark::gadget<FieldT>
{
private:
    // input variable block = {x, y}
    std::shared_ptr<libsnark::block_variable<FieldT>> block;

    // Hash gadget used as a commitment
    std::shared_ptr<HashT> hasher;

    // hash digest = HashT(x || y)
    std::shared_ptr<libsnark::digest_variable<FieldT>> result;

public:
    COMM_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable_array<FieldT> &x,
        const libsnark::pb_variable_array<FieldT> &y,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
        const std::string &annotation_prefix = "COMM_gadget");
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

// See Zerocash extended paper, page 22
// The commitment cm is computed as
// HashT(HashT( trap_r || [HashT(a_pk, rho)]_[128]) || "0"*192 || v)
// We denote by trap_r the trapdoor r
template<typename FieldT, typename HashT>
class COMM_cm_gadget : public libsnark::gadget<FieldT>
{
private:
    // input variable
    libsnark::pb_variable_array<FieldT> input;
    libsnark::pb_variable_array<FieldT> a_pk;
    libsnark::pb_variable_array<FieldT> rho;
    libsnark::pb_variable_array<FieldT> trap_r;
    libsnark::pb_variable_array<FieldT> value_v;
    std::shared_ptr<libsnark::digest_variable<FieldT>> temp_result;

    // Hash gadgets used as inner, outer and final commitments
    std::shared_ptr<COMM_gadget<FieldT, HashT>> com_gadget;

    // Packing gadget to output field element
    std::shared_ptr<libsnark::packing_gadget<FieldT>> bits_to_field;

public:
    COMM_cm_gadget(
        libsnark::protoboard<FieldT> &pb,
        // ZethNote public address key, 256 bits
        const libsnark::pb_variable_array<FieldT> &a_pk,
        // ZethNote nullifier's preimage, 256 bits
        const libsnark::pb_variable_array<FieldT> &rho,
        // ZethNote randomness, 256 bits
        const libsnark::pb_variable_array<FieldT> &trap_r,
        // ZethNote value 64 bits
        const libsnark::pb_variable_array<FieldT> &value_v,
        libsnark::pb_variable<FieldT> result,
        const std::string &annotation_prefix = "COMM_cm_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

} // namespace libzeth

#include "libzeth/circuits/commitments/commitment.tcc"

#endif // __ZETH_CIRCUITS_COMMITMENT_HPP__
