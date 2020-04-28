// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_TYPES_EXTENDED_PROOF_TCC__
#define __ZETH_TYPES_EXTENDED_PROOF_TCC__

#include "libzeth/core/extended_proof.hpp"
#include "libzeth/core/ff_utils.hpp"

namespace libzeth
{

template<typename ppT, typename snarkT>
extended_proof<ppT, snarkT>::extended_proof(
    typename snarkT::ProofT &in_proof,
    libsnark::r1cs_primary_input<libff::Fr<ppT>> &in_primary_inputs)
{
    proof = std::make_shared<typename snarkT::ProofT>(in_proof);
    primary_inputs =
        std::make_shared<libsnark::r1cs_primary_input<libff::Fr<ppT>>>(
            in_primary_inputs);
}

template<typename ppT, typename snarkT>
const typename snarkT::ProofT &extended_proof<ppT, snarkT>::get_proof() const
{
    return *this->proof;
}

template<typename ppT, typename snarkT>
const libsnark::r1cs_primary_input<libff::Fr<ppT>>
    &extended_proof<ppT, snarkT>::get_primary_inputs() const
{
    return *this->primary_inputs;
}

template<typename ppT, typename snarkT>
void extended_proof<ppT, snarkT>::write_primary_inputs(
    boost::filesystem::path path) const
{
    if (path.empty()) {
        // Used for debugging purpose
        boost::filesystem::path tmp_path = get_path_to_debug_directory();
        boost::filesystem::path primary_input_json_file("primary_input.json");
        path = tmp_path / primary_input_json_file;
    }
    // Convert the boost path into char*
    const char *str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    ss << "{\n";
    ss << " \"inputs\" :"
       << "["; // 1 should always be the first variable passed
    for (size_t i = 0; i < *this->primary_inputs.size(); ++i) {
        ss << "\"0x"
           << libsnark_bigint_to_hexadecimal_str<libff::Fr<ppT>>(
                  *this->primary_inputs[i].as_bigint())
           << "\"";
        if (i < *this->primary_inputs.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]\n";
    ss << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename ppT, typename snarkT>
void extended_proof<ppT, snarkT>::dump_primary_inputs() const
{
    std::cout << "{\n";
    std::cout << " \"inputs\" :"
              << "["; // 1 should always be the first variable passed
    for (size_t i = 0; i < (*this->primary_inputs).size(); ++i) {
        std::cout << "\"0x"
                  << libsnark_bigint_to_hexadecimal_str<libff::Fr<ppT>>(
                         (*this->primary_inputs)[i].as_bigint())
                  << "\"";
        if (i < (*this->primary_inputs).size() - 1) {
            std::cout << ", ";
        }
    }
    std::cout << "]\n";
    std::cout << "}";
}

template<typename ppT, typename snarkT>
void extended_proof<ppT, snarkT>::write_proof(
    boost::filesystem::path path) const
{
    snarkT::proof_to_json(*this->proof, path);
}

template<typename ppT, typename snarkT>
void extended_proof<ppT, snarkT>::write_extended_proof(
    boost::filesystem::path path) const
{
    snarkT::proof_and_inputs_to_json(*proof, *primary_inputs, path);
}

template<typename ppT, typename snarkT>
void extended_proof<ppT, snarkT>::dump_proof() const
{
    snarkT::display_proof(*this->proof);
}

} // namespace libzeth

#endif // __ZETH_TYPES_EXTENDED_PROOF_TCC__
