#ifndef __ZETH_CIRCUIT_WRAPPER_TCC__
#define __ZETH_CIRCUIT_WRAPPER_TCC__

#include "zeth.h"

namespace libzeth {

template<typename FieldT, typename HashT, typename HashTreeT, typename ppT, size_t NumInputs, size_t NumOutputs>
keyPairT<ppT> CircuitWrapper<FieldT, HashT, HashTreeT, ppT, NumInputs, NumOutputs>::generate_trusted_setup() {
    libsnark::protoboard<FieldT> pb;
    joinsplit_gadget<FieldT, HashT, HashTreeT, NumInputs, NumOutputs> g(pb);
    g.generate_r1cs_constraints();

    // Generate a verification and proving key (trusted setup)
    // and write them in a file
    keyPairT<ppT> keypair = gen_trusted_setup<ppT>(pb);
    writeSetup<ppT>(keypair, this->setupPath);

    return keypair;
}

template<typename FieldT, typename HashT, typename HashTreeT, typename ppT, size_t NumInputs, size_t NumOutputs>
extended_proof<ppT> CircuitWrapper<FieldT, HashT, HashTreeT, ppT, NumInputs, NumOutputs>::prove(
    const FieldT& root,
    const std::array<JSInput<FieldT>, NumInputs>& inputs,
    const std::array<ZethNote, NumOutputs>& outputs,
    bits64 vpub_in,
    bits64 vpub_out,
    const bits256 h_sig_in,
    const bits256 phi_in,
    provingKeyT<ppT> proving_key
) {
    // left hand side and right hand side of the joinsplit
    bits64 lhs_value = vpub_in;
    bits64 rhs_value = vpub_out;

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
    // due to a violation of the constraint:
    // `1 * left_value = right_value` in the JoinSplit circuit
    if (lhs_value != rhs_value) {
        throw std::invalid_argument("invalid joinsplit balance");
    }

    libsnark::protoboard<FieldT> pb;
    joinsplit_gadget<FieldT, HashT, HashTreeT, NumInputs, NumOutputs> g(pb);
    g.generate_r1cs_constraints();
    g.generate_r1cs_witness(
        root,
        inputs,
        outputs,
        vpub_in,
        vpub_out,
        h_sig_in,
        phi_in
    );

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "******* [DEBUG] Satisfiability result: " << is_valid_witness << " *******" << std::endl;

    // Write the extended proof in a file (Default path is taken if not specified)
    proofT<ppT> proof = libzeth::gen_proof<ppT>(pb, proving_key);
    libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input = pb.primary_input();

    // Instantiate an extended_proof from the proof we generated and the given primary_input
    extended_proof<ppT> ext_proof = extended_proof<ppT>(proof, primary_input);
    ext_proof.write_extended_proof();

    return ext_proof;
}

} // libzeth

#endif // __ZETH_CIRCUIT_WRAPPER_TCC__