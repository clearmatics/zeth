// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_PRFS_PRF_HPP__
#define __ZETH_CIRCUITS_PRFS_PRF_HPP__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/prfs.tcc

#include "libzeth/circuits/circuit_utils.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>

namespace libzeth
{

template<typename FieldT, typename HashT>
class PRF_gadget : public libsnark::gadget<FieldT>
{
private:
    std::shared_ptr<libsnark::digest_variable<FieldT>> result;
    libsnark::block_variable<FieldT> block;
    HashT hasher;

public:
    PRF_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable_array<FieldT> &x,
        const libsnark::pb_variable_array<FieldT> &y,
        std::shared_ptr<libsnark::digest_variable<FieldT>>
            result, // blake2sCompress(x || y)
        const std::string &annotation_prefix = "PRF_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

// This function is useful as the generation of a_pk is done via a_pk =
// blake2sCompress(a_sk || 0^256) See Zerocash extended paper, page 22,
// paragraph "Instantiating the NP statement POUR"
template<typename FieldT, typename HashT>
libsnark::pb_variable_array<FieldT> gen_256_zeroes(
    const libsnark::pb_variable<FieldT> &ZERO);

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_addr(
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &x);

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_nf(
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &a_sk);

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_pk(
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &a_sk,
    size_t index);

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_rho(
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &phi,
    size_t index);

/// PRF to generate the public addresses
/// a_pk = blake2sCompress("1100" || [a_sk]_252 || 0^256): See ZCash protocol
/// specification paper, page 57
template<typename FieldT, typename HashT>
class PRF_addr_a_pk_gadget : public PRF_gadget<FieldT, HashT>
{
public:
    PRF_addr_a_pk_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable<FieldT> &ZERO,
        const libsnark::pb_variable_array<FieldT> &a_sk,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
        const std::string &annotation_prefix = " add_PRF_gadget");
};

/// PRF to generate the nullifier
/// nf = blake2sCompress("1110" || [a_sk]_252 || rho): See ZCash protocol
/// specification paper, page 57
template<typename FieldT, typename HashT>
class PRF_nf_gadget : public PRF_gadget<FieldT, HashT>
{
public:
    PRF_nf_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable<FieldT> &ZERO,
        const libsnark::pb_variable_array<FieldT> &a_sk,
        const libsnark::pb_variable_array<FieldT> &rho,
        std::shared_ptr<libsnark::digest_variable<FieldT>>
            result, // blake2sCompress(a_sk || 01 || [rho]_254)
        const std::string &annotation_prefix = "PRF_nf_gadget");
};

/// PRF to generate the h_i
/// h_i = blake2sCompress("0" || index || "00" || [a_sk]_252 || h_sig)
/// See ZCash protocol specification paper, page 57
template<typename FieldT, typename HashT>
class PRF_pk_gadget : public PRF_gadget<FieldT, HashT>
{
public:
    PRF_pk_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable<FieldT> &ZERO,
        const libsnark::pb_variable_array<FieldT> &a_sk,
        const libsnark::pb_variable_array<FieldT> &h_sig,
        size_t index,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
        const std::string &annotation_prefix = " pk_PRF_gadget");
};

/// PRF to generate rho
/// rho_i = blake2sCompress( "0" || index || "10" || [phi]_252 || h_sig)
/// See ZCash protocol specification paper, page 57
template<typename FieldT, typename HashT>
class PRF_rho_gadget : public PRF_gadget<FieldT, HashT>
{
public:
    PRF_rho_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable<FieldT> &ZERO,
        const libsnark::pb_variable_array<FieldT> &phi,
        const libsnark::pb_variable_array<FieldT> &h_sig,
        size_t index,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
        const std::string &annotation_prefix = " rho_PRF_gadget");
};

} // namespace libzeth

#include "libzeth/circuits/prfs/prf.tcc"

#endif // __ZETH_CIRCUITS_PRFS_PRF_HPP__
