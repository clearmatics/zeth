pragma solidity ^0.5.0;

import "./Groth16Verifier.sol";
import "./BaseMixer.sol";

contract Groth16Mixer is BaseMixer {
    // zkSNARK verifier smart contract
    Groth16Verifier public zksnark_verifier;

    // Constructor
    constructor(address verifier_address, uint mk_depth, address token_address, address hasher_address) BaseMixer(mk_depth, token_address, hasher_address) public {
        zksnark_verifier = Groth16Verifier(verifier_address);
    }

    // This function allows to mix coins and execute payments in zero knowledge
    function mix (
        string memory ciphertext1,
        string memory ciphertext2, // Nb of ciphertexts depends on the JS description (Here 2 inputs)
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[] memory input
    ) public payable {
        // 1. Check the root and the nullifiers
        assemble_root_and_nullifiers_and_append_to_state(input);

        // 2. Verify the proof
        require(
            zksnark_verifier.verifyTx(a, b, c, input),
            "Invalid proof: Unable to verify the proof correctly"
        );

        // 3. Append the commitments to the tree
        assemble_commitments_and_append_to_state(input);

        // 4. get the public values in Wei and modify the state depending on their values
        process_public_values(input);

        // 5. Add the new root to the list of existing roots and emit it
        bytes32 currentRoot = getRoot();
        add_and_emit_merkle_root(currentRoot);

        // Emit the all the coins' secret data encrypted with the recipients' respective keys
        emit_ciphertexts(ciphertext1, ciphertext2);
    }
}
