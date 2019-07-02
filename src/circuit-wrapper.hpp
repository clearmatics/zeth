#ifndef __ZETH_CIRCUIT_WRAPPER_HPP__
#define __ZETH_CIRCUIT_WRAPPER_HPP__

#include "types/note.hpp"

#include "circuits/joinsplit.tcc"
#include "libsnark_helpers/libsnark_helpers.hpp"

// zkSNARK specific aliases and imports
#include "snarks_alias.hpp"
#include "snarks_core_imports.hpp"

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT; // We instantiate the field from the ppT of the curve we use
typedef MiMC_hash_gadget<FieldT> HashT; // We instantiate the HashT with MimCHash



namespace libzeth {

template<typename FieldT, typename HashT, size_t NumInputs, size_t NumOutputs>
class CircuitWrapper {
public:
    typedef libff::default_ec_pp ppT; // We use the public paramaters (ppT) of the curve used in the CMakeLists.txt

    libsnark::protoboard<FieldT> pb;
    boost::filesystem::path setupPath;
    std::shared_ptr<joinsplit_gadget<FieldT, HashT, NumInputs, NumOutputs>> joinsplit_g;

    CircuitWrapper(
        const boost::filesystem::path setupPath = ""
    ): setupPath(setupPath) {};

    // Generate the trusted setup
    keyPairT<ppT> generate_trusted_setup();

    // Generate a proof and returns an extended proof
    extended_proof<ppT> prove(const FieldT& root_bits,
                            const std::array<JSInput<FieldT>, NumInputs>& inputs,
                            const std::array<ZethNote<FieldT>, NumOutputs>& outputs,
                            FieldT vpub_in,
                            FieldT vpub_out,
                            provingKeyT<ppT> proving_key);
};

} // libzeth
#include "circuit-wrapper.tcc"

#endif // __ZETH_CIRCUIT_WRAPPER_HPP__
