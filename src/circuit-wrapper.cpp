#include "circuit-wrapper.hpp"
#include "prover/computation.hpp"
#include "joinsplit.hpp"
#include "note.hpp"

#include "prover/gadget.tcc"

namespace libzeth {

libsnark::r1cs_ppzksnark_keypair<ppT> CircuitWrapper<NumInputs, NumOutputs>::generate_trusted_setup() {
    protoboard<FieldT> pb;

    joinsplit_gadget<FieldT, HashT, NumInputs, NumOutputs> g(pb);
    g.generate_r1cs_constraints();
    
    // Generate a verification and proving key (trusted setup)
    libsnark::r1cs_ppzksnark_keypair<ppT> keypair = gen_trusted_setup<ppT>(pb);

    // Write the keys in a file
    write_setup<ppT>(keypair, this->keysPath); // Take the default path

    return keypair;
}

extended_proof<ppT> prove(
    bits256 root_bits, // We use the same root across all JSInputs
    const std::array<JSInput, NumInputs>& inputs,
    const std::array<ZethNote, NumOutputs>& outputs,
    uint64_t vpub,
    libsnark::r1cs_ppzksnark_proving_key<ppT> proving_key
) {
        // left hand side and right hand side of the joinsplit
        uint64_t lhs_value = 0;
        uint64_t rhs_value = vpub;

        // Compute the sum on the left hand side of the joinsplit
        for (size_t i = 0; i < NumInputs; i++) {
                lhs_value += inputs[i].note.value();
        }

        // Compute the sum on the right hand side of the joinsplit
        for (size_t i = 0; i < NumOutputs; i++) {
                rhs_value += outputs[i].value();
        }

        // Make sure that the balance betweem rhs and lfh is respected
        if (lhs_value != rhs_value) {
            throw std::invalid_argument("invalid joinsplit balance");
        }

        protoboard<FieldT> pb;

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

} // libzeth