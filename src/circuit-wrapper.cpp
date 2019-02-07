#include "computation.hpp"
#include "joinsplit.hpp"
#include "note.hpp"

#include "gadget.tcc"

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
    boost::filesystem::path setupPath;
    std::shared_ptr<joinsplit_gadget<FieldT, HashT, NumInputs, NumOutputs>> joinsplit_g;

    CircuitWrapper(
        const boost::filesystem::path setupPath = ""
    ): setupPath(setupPath) {};

    // Generate the trusted setup
    libsnark::r1cs_ppzksnark_keypair<ppT> generate_trusted_setup() {
        libsnark::protoboard<FieldT> pb;

        joinsplit_gadget<FieldT, HashT, NumInputs, NumOutputs> g(pb);
        g.generate_r1cs_constraints();
            
        // Generate a verification and proving key (trusted setup)
        libsnark::r1cs_ppzksnark_keypair<ppT> keypair = gen_trusted_setup<ppT>(pb);

        // Write the keys in a file
        write_setup<ppT>(keypair, this->setupPath); // Take the default path

        return keypair;
    }

    // Generate a proof and returns an extended proof
    extended_proof<ppT> prove(
        const bits256& root_bits,
        const std::array<JSInput, NumInputs>& inputs,
        const std::array<ZethNote, NumOutputs>& outputs,
        bits64 vpub,
        libsnark::r1cs_ppzksnark_proving_key<ppT> proving_key
    ) {
        // left hand side and right hand side of the joinsplit
        std::array<bool, 64> zero_array;
        zero_array.fill(0);
        bits64 lhs_value = zero_array;
        bits64 rhs_value = vpub;

        // Compute the sum on the left hand side of the joinsplit
        for (size_t i = 0; i < NumInputs; i++) {
            lhs_value = binaryAddition<64>(lhs_value, inputs[i].note.value());
        }

        // Compute the sum on the right hand side of the joinsplit
        for (size_t i = 0; i < NumOutputs; i++) {
            rhs_value = binaryAddition<64>(rhs_value, outputs[i].value());
        }

        // [CHECK] Make sure that the balance between rhs and lfh is respected
        // Used to stop any proof computation that would inevitably fail
        // due to a violation of the equality:
        // left_value = right_value
        // in the JoinSplit
        if (lhs_value != rhs_value) {
            throw std::invalid_argument("invalid joinsplit balance");
        }

        libsnark::protoboard<FieldT> pb;

        joinsplit_gadget<FieldT, HashT, NumInputs, NumOutputs> g(pb);
        g.generate_r1cs_constraints();
        g.generate_r1cs_witness(
            root_bits,
            inputs,
            outputs,
            vpub
        );

        bool is_valid_witness = pb.is_satisfied();
        std::cout << "******* [DEBUG] Satisfiability result: " << is_valid_witness << " *******" << std::endl;

        // Build a proof using the witness built above and the proving key generated during the trusted setup
        extended_proof<ppT> ext_proof = gen_proof<ppT>(pb, proving_key);
        // Write the extended proof in a file
        ext_proof.write_extended_proof(); // Take the default path

        return ext_proof;
    }
};

} // libzeth