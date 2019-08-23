pragma solidity ^0.5.0;

import "./OTSchnorrVerifier.sol";
import "./Groth16Verifier.sol";
import "./BaseMixer.sol";

contract Groth16Mixer is BaseMixer {
    // zkSNARK verifier smart contract
    Groth16Verifier public zksnark_verifier;
    // OT-Signature verifier smart contract
    OTSchnorrVerifier public otsig_verifier;

    // Constructor
    constructor(address snark_ver, address sig_ver, uint mk_depth, address token, address hasher) BaseMixer(mk_depth, token, hasher) public {
        zksnark_verifier = Groth16Verifier(snark_ver);
        otsig_verifier = OTSchnorrVerifier(sig_ver);
    }

    // This function allows to mix coins and execute payments in zero knowledge
    function mix (
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[2][2] memory vk,
        uint sigma,
        uint[] memory input,
        bytes32 pk_sender,
        bytes memory ciphertext0,
        bytes memory ciphertext1 // The nb of ciphertexts depends on the JS description (Here 2 inputs)
    ) public payable {
        // 1. Check the root and the nullifiers
        assemble_root_and_nullifiers_and_append_to_state(input);

        // 2.a Verify the proof
        require(
            zksnark_verifier.verifyTx(a, b, c, input),
            "Invalid proof: Unable to verify the proof correctly"
        );

        // 2.b Verify the signature
        bytes32 hash_proof = sha256(abi.encodePacked(a, b, c));
        bytes32 hash_ciphers = sha256(abi.encodePacked(pk_sender,ciphertext0, ciphertext1));
        require(
            otsig_verifier.verify(
                vk,
                sigma,
                hash_ciphers,
                hash_proof,
                assemble_primary_inputs_and_hash(input)
            ),
            "Invalid signature: Unable to verify the signature correctly"
        );

        // 3. Append the commitments to the tree
        assemble_commitments_and_append_to_state(input);

        // 4. get the public values in Wei and modify the state depending on their values
        process_public_values(input);

        // 5. Add the new root to the list of existing roots and emit it
        add_and_emit_merkle_root(getRoot());

        // Emit the all the coins' secret data encrypted with the recipients' respective keys
        emit_ciphertexts(pk_sender, ciphertext0, ciphertext1);
    }
}
