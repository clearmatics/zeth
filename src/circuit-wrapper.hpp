#ifndef __ZETH_CIRCUIT_WRAPPER_HPP__
#define __ZETH_CIRCUIT_WRAPPER_HPP__

#include "circuits/joinsplit.tcc"
#include "libsnark_helpers/libsnark_helpers.hpp"
#include "types/note.hpp"

// zkSNARK specific aliases and imports
#include "snarks_alias.hpp"
#include "snarks_core_imports.hpp"

namespace libzeth
{

template<
    typename FieldT,
    typename HashT,
    typename HashTreeT,
    typename ppT,
    size_t NumInputs,
    size_t NumOutputs>
class circuit_wrapper
{
public:
    boost::filesystem::path setup_path;
    std::shared_ptr<
        joinsplit_gadget<FieldT, HashT, HashTreeT, NumInputs, NumOutputs>>
        joinsplit_g;

    circuit_wrapper(const boost::filesystem::path setup_path = "")
        : setup_path(setup_path){};

    // Generate the trusted setup
    keyPairT<ppT> generate_trusted_setup() const;

    // Generate a proof and returns an extended proof
    extended_proof<ppT> prove(
        const FieldT &root,
        const std::array<joinsplit_input<FieldT>, NumInputs> &inputs,
        const std::array<zeth_note, NumOutputs> &outputs,
        bits64 vpub_in,
        bits64 vpub_out,
        const bits256 h_sig_in,
        const bits256 phi_in,
        const provingKeyT<ppT> &proving_key) const;
};

} // namespace libzeth
#include "circuit-wrapper.tcc"

#endif // __ZETH_CIRCUIT_WRAPPER_HPP__