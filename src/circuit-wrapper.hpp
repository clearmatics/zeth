#ifndef __ZETH_CIRCUIT_WRAPPER_HPP__
#define __ZETH_CIRCUIT_WRAPPER_HPP__

#include "types/note.hpp"

#include "circuits/joinsplit.tcc"
#include "libsnark_helpers/libsnark_helpers.hpp"

// zkSNARK specific aliases and imports
#include "snarks_alias.hpp"
#include "snarks_core_imports.hpp"

typedef libff::default_ec_pp ppT;

namespace libzeth {

template<typename FieldT, size_t NumInputs, size_t NumOutputs>
class CircuitWrapper {
public:
    typedef libff::default_ec_pp ppT; // We use the public paramaters (ppT) of the curve used in the CMakeLists.txt
    typedef MiMC_mp_gadget<FieldT> HashTreeT; // We instantiate the HashTreeT with MiMC compression function

    libsnark::protoboard<FieldT> pb;
    boost::filesystem::path setupPath;
    std::shared_ptr<joinsplit_gadget<FieldT, HashTreeT, NumInputs, NumOutputs>> joinsplit_g;

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
                            provingKeyT<ppT> proving_key);
};

} // libzeth
#include "circuit-wrapper.tcc"

#endif // __ZETH_CIRCUIT_WRAPPER_HPP__
