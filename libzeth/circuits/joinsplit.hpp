// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_JOINSPLIT_HPP__
#define __ZETH_CIRCUITS_JOINSPLIT_HPP__

#include "libzeth/circuits/notes/note.hpp"
#include "libzeth/circuits/safe_arithmetic.hpp"
#include "libzeth/core/joinsplit_input.hpp"
#include "libzeth/core/merkle_tree_field.hpp"
#include "libzeth/zeth_constants.hpp"

namespace libzeth
{

template<
    typename FieldT,
    typename HashT,
    typename HashTreeT,
    size_t NumInputs,
    size_t NumOutputs,
    size_t TreeDepth>
class joinsplit_gadget : libsnark::gadget<FieldT>
{
public:
    // Primary inputs are packed to be added to the extended proof and given to
    // the verifier on-chain
    explicit joinsplit_gadget(
        libsnark::protoboard<FieldT> &pb,
        const std::string &annotation_prefix = "joinsplit_gadget");

    void generate_r1cs_constraints();

    void generate_r1cs_witness(
        const FieldT &rt,
        const std::array<joinsplit_input<FieldT, TreeDepth>, NumInputs> &inputs,
        const std::array<zeth_note, NumOutputs> &outputs,
        bits64 vpub_in,
        bits64 vpub_out,
        const bits256 h_sig_in,
        const bits256 phi_in);

    // Computes the number of field elements in the public data
    static size_t get_num_public_elements();

private:
    // Given a digest variable, assign to an unpacked field element
    // `unpacked_element` and unpacked element holding residual bits.
    static void digest_variable_assign_to_field_element_and_residual(
        const libsnark::digest_variable<FieldT> &digest_var,
        libsnark::pb_variable_array<FieldT> &unpacked_element,
        libsnark::pb_variable_array<FieldT> &unpacked_residual_bits);

    static void assign_public_value_to_residual_bits(
        const libsnark::pb_variable_array<FieldT> &unpacked_public_value,
        libsnark::pb_variable_array<FieldT> &unpacked_residual_bits);

    // Computes the total bit-length of the primary inputs
    static size_t get_inputs_bit_size();

    // Computes the total bit-length of the unpacked primary inputs
    static size_t get_unpacked_inputs_bit_size();

    const size_t digest_len_minus_field_cap =
        subtract_with_clamp(HashT::get_digest_len(), FieldT::capacity());

    // Number of residual bits from packing of hash digests into smaller
    // field elements to which are added the public value of size 64 bits
    const size_t length_bit_residual =
        2 * ZETH_V_SIZE + digest_len_minus_field_cap * (1 + 2 * NumInputs);
    // Number of field elements needed to pack this number of bits
    const size_t nb_field_residual =
        libff::div_ceil(length_bit_residual, FieldT::capacity());

    // Multipacking gadgets for the inputs (nullifierS, hsig, message
    // authentication tags (h_is) and the residual bits (comprising the
    // previous variables' bits not containable in a single field element as
    // well as the public values) (the root and cms are field elements)
    // because we pack the nullifiers (Inputs of JS = NumInputs),
    // AND the signature hash h_sig (+1) AND the message authentication tags
    // h_iS (+ NumInputs) AND the residual field elements
    // which aggregate the extra bits and public values (+1)
    std::array<
        libsnark::pb_variable_array<FieldT>,
        NumInputs + 1 + NumInputs + 1>
        packed_inputs;
    std::array<
        libsnark::pb_variable_array<FieldT>,
        NumInputs + 1 + NumInputs + 1>
        unpacked_inputs;

    // We use an array of multipackers here instead of a single packer that
    // packs everything.
    std::array<
        std::shared_ptr<libsnark::multipacking_gadget<FieldT>>,
        NumInputs + 1 + NumInputs + 1>
        packers;

    libsnark::pb_variable<FieldT> ZERO;

    // PUBLIC DATA: to be made available to the mixer

    // Merkle Root
    std::shared_ptr<libsnark::pb_variable<FieldT>> merkle_root;
    // List of nullifiers of the notes to spend
    std::array<std::shared_ptr<libsnark::digest_variable<FieldT>>, NumInputs>
        input_nullifiers;
    // List of commitments generated for the new notes
    libsnark::pb_variable_array<FieldT> output_commitments;
    // Public value that is put into the mix
    libsnark::pb_variable_array<FieldT> zk_vpub_in;
    // Value that is taken out of the mix
    libsnark::pb_variable_array<FieldT> zk_vpub_out;
    // Sighash h_sig := hSigCRH(randomSeed, {nf_old},
    // joinSplitPubKey) (p.53 ZCash proto. spec.)
    std::shared_ptr<libsnark::digest_variable<FieldT>> h_sig;
    // List of message authentication tags
    std::array<std::shared_ptr<libsnark::digest_variable<FieldT>>, NumInputs>
        h_is;

    // PRIVATE DATA: must be auxiliary (private) inputs to the statement.
    // Protoboard owner is responsible for ensuring this. (Note that the PUBLIC
    // inputs above are allocated first, so only the first
    // get_num_public_elements allocated by this gadget are "public").

    // Total amount transfered in the transaction
    libsnark::pb_variable_array<FieldT> zk_total_uint64;
    // List of all spending keys
    std::array<std::shared_ptr<libsnark::digest_variable<FieldT>>, NumInputs>
        a_sks;
    // List of all output rhos
    std::array<std::shared_ptr<libsnark::digest_variable<FieldT>>, NumOutputs>
        rho_is;
    // random seed for uniqueness of the new rho
    std::shared_ptr<libsnark::digest_variable<FieldT>> phi;

    // Input note gadgets
    std::array<
        std::shared_ptr<input_note_gadget<FieldT, HashT, HashTreeT, TreeDepth>>,
        NumInputs>
        input_notes;
    // Message authentication tag gadgets
    std::array<std::shared_ptr<PRF_pk_gadget<FieldT, HashT>>, NumInputs>
        h_i_gadgets;

    // Rho PRF gadgets
    std::array<std::shared_ptr<PRF_rho_gadget<FieldT, HashT>>, NumOutputs>
        rho_i_gadgets;
    // Output note gadgets
    std::array<std::shared_ptr<output_note_gadget<FieldT, HashT>>, NumOutputs>
        output_notes;

    // Make sure that we do not exceed the number of inputs/outputs
    // specified in zeth's configuration file (see: zeth.h file)
    static_assert(NumInputs <= ZETH_NUM_JS_INPUTS, "invalid NumInputs");
    static_assert(NumOutputs <= ZETH_NUM_JS_OUTPUTS, "invalid NumOutputs");
};

} // namespace libzeth

#include "libzeth/circuits/joinsplit.tcc"

#endif // __ZETH_CIRCUITS_JOINSPLIT_HPP__
