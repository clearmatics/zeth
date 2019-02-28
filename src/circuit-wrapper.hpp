#ifndef __ZETH_CIRCUIT_WRAPPER_HPP__
#define __ZETH_CIRCUIT_WRAPPER_HPP__

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include "libsnark_helpers/extended_proof.hpp"
#include "types/note.hpp"

#include "circuits/joinsplit.tcc"


namespace libzeth {

template<size_t NumInputs, size_t NumOutputs>
class CircuitWrapper {
public:
    typedef libff::default_ec_pp ppT; // We use the public paramaters (ppT) of the curve used in the CMakeLists.txt
    typedef libff::Fr<ppT> FieldT; // We instantiate the field from the ppT of the curve we use
    typedef sha256_ethereum<FieldT> HashT; // We instantiate the HashT with sha256_ethereum

    libsnark::protoboard<FieldT> pb;
    boost::filesystem::path setupPath;
    std::shared_ptr<joinsplit_gadget<FieldT, HashT, NumInputs, NumOutputs>> joinsplit_g;

    CircuitWrapper(
        const boost::filesystem::path setupPath = ""
    ): setupPath(setupPath) {};

    // Generate the trusted setup
    libsnark::r1cs_ppzksnark_keypair<ppT> generate_trusted_setup();

    // Generate a proof and returns an extended proof
    extended_proof<ppT> prove(const bits256& root_bits,
                            const std::array<JSInput, NumInputs>& inputs,
                            const std::array<ZethNote, NumOutputs>& outputs,
                            bits64 vpub_in,
                            bits64 vpub_out,
                            libsnark::r1cs_ppzksnark_proving_key<ppT> proving_key);
};

} // libzeth
#include "circuit-wrapper.tcc"

#endif // __ZETH_CIRCUIT_WRAPPER_HPP__