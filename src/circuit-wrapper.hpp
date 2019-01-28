// This file should be wrapper around the prover circuit and should basically generate 
// all the data necessary to be fed into the gagdets (ie: this function should build the witness)
// Once the assignement of the circuit is built, we should call the circuits/gagdets with
// the appropriate input and generate the proof

// We want all our gadgets to respect the common gadget interface (ie: implement the
// "generate_r1cs_constraints" and the "generate_r1cs_witness" functions)
// This file should wrap everything around, call the functions to do I/O of the proof, and parse the
// user input to feed it into the gadgets.

// The idea is to have somehting like zcash did here: https://github.com/zcash/zcash/blob/0f091f228cdb1793a10ea59f82b7c7f0b93edb7a/src/zcash/circuit/gadget.tcc
// This gadget basically imports all other gadgets (subcircuits) in order to
// build the joinsplit circuit which is the main gadget/whole circuit
// Then the .tcc circuit is wrapped by cpp code that parses everything that needs to be fed into
// the circuit

namespace libzeth {

template<size_t NumInputs, size_t NumOutputs>
class CircuitWrapper {
    public:
        typedef libff::default_ec_pp ppT; // We use the public paramaters (ppT) of the curve used in the CMakeLists.txt
        typedef libff::Fr<ppT> FieldT; // We instantiate the field from the ppT of the curve we use
        typedef sha256_ethereum<FieldT> HashT; // We instantiate the HashT with sha256_ethereum

        protoboard<FieldT> pb;
        boost::filesystem::path vkPath;
        boost::filesystem::path pkPath;
        std::shared_ptr<joinsplit_gadget<FieldT, HashT, NumInputs, NumOutputs>> joinsplit_g;

        CircuitWrapper(const boost::filesystem::path vkPath, const boost::filesystem::path pkPath): vkPath(vkPath), pkPath(pkPath) {};

        // Generate the trusted setup
        libsnark::r1cs_ppzksnark_keypair<ppT> generate_trusted_setup();

        // Generate a proof and returns an extended proof
        extended_proof<ppT> prove(
            libff::bit_vector root_bits,
            const std::array<JSInput, NumInputs>& inputs,
            const std::array<ZethNote, NumOutputs>& outputs,
            uint64_t vpub,
            libsnark::r1cs_ppzksnark_proving_key<ppT> proving_key
        );
}

} // libzeth