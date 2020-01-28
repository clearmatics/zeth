// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

import "./OTSchnorrVerifier.sol";
import "./Pghr13Verifier.sol";
import "./BaseMixer.sol";

contract Pghr13Mixer is BaseMixer {
    // zkSNARK verifier smart contract
    Pghr13Verifier public zksnark_verifier;
    // OT-Signature verifier smart contract
    OTSchnorrVerifier public otsig_verifier;

    // Constructor
    constructor(address snark_ver, address sig_ver, uint mk_depth, address token, address hasher) BaseMixer(mk_depth, token, hasher) public {
        zksnark_verifier = Pghr13Verifier(snark_ver);
        otsig_verifier = OTSchnorrVerifier(sig_ver);
    }

    // This function allows to mix coins and execute payments in zero knowledge
    function mix (
        uint[2] memory a,
        uint[2] memory a_p,
        uint[2][2] memory b,
        uint[2] memory b_p,
        uint[2] memory c,
        uint[2] memory c_p,
        uint[2] memory h,
        uint[2] memory k,
        uint[2][2] memory vk,
        uint sigma,
        uint[] memory input,
        bytes32 pk_sender,
        bytes memory ciphertext0,
        bytes memory ciphertext1 // Nb of ciphertexts depends on the JS description (Here 2 inputs)
        ) public payable {
        // 1. Check the root and the nullifiers
        check_mkroot_nullifiers_hsig_append_nullifiers_state(vk, input);

        // 2.a Verify the signature on the hash of data_to_be_signed
        bytes32 hash_to_be_signed = sha256(
            abi.encodePacked(
                pk_sender,
                ciphertext0,
                ciphertext1,
                a,
                a_p,
                b,
                b_p,
                c,
                c_p,
                h,
                k,
                input
            )
        );
        require(
            otsig_verifier.verify(
                vk,
                sigma,
                hash_to_be_signed
            ),
            "Invalid signature: Unable to verify the signature correctly"
        );

        // 2.b Verify the proof
        require(
            zksnark_verifier.verifyTx(a, a_p, b, b_p, c, c_p, h, k, input),
            "Invalid proof: Unable to verify the proof correctly"
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
