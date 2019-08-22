#ifndef __ZETH_CIRCUIT_WRAPPER_HPP__
#define __ZETH_CIRCUIT_WRAPPER_HPP__

#include "types/note.hpp"

#include "circuits/joinsplit.tcc"
#include "libsnark_helpers/libsnark_helpers.hpp"

// zkSNARK specific aliases and imports
#include "snarks_alias.hpp"
#include "snarks_core_imports.hpp"

namespace libzeth {

template<typename FieldT, typename HashT, typename HashTreeT, typename ppT, size_t NumInputs, size_t NumOutputs>
class CircuitWrapper {
public:
    libsnark::protoboard<FieldT> pb;
    boost::filesystem::path setupPath;
    std::shared_ptr<joinsplit_gadget<FieldT, HashT, HashTreeT, NumInputs, NumOutputs>> joinsplit_g;

    CircuitWrapper(
        const boost::filesystem::path setupPath = ""
    ): setupPath(setupPath) {};

    // Generate the trusted setup
    keyPairT<ppT> generate_trusted_setup();

    // Generate a proof and returns an extended proof
    extended_proof<ppT> prove(const FieldT& root,
                            const std::array<JSInput<FieldT>, NumInputs>& inputs,
                            const std::array<ZethNote, NumOutputs>& outputs,
                            bits64 vpub_in,
                            bits64 vpub_out,
                            const bits256 h_sig_in,
                            const bits256 phi_in,
                            provingKeyT<ppT> proving_key);
};

} // libzeth
#include "circuit-wrapper.tcc"

#endif // __ZETH_CIRCUIT_WRAPPER_HPP__
