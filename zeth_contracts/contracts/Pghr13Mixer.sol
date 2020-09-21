// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

import "./OTSchnorrVerifier.sol";
import "./Pairing.sol";
import "./BaseMixer.sol";

contract Pghr13Mixer is BaseMixer {

    struct VerifyingKey {
        Pairing.G2Point A;
        Pairing.G1Point B;
        Pairing.G2Point C;
        Pairing.G2Point gamma;
        Pairing.G1Point gammaBeta1;
        Pairing.G2Point gammaBeta2;
        Pairing.G2Point Z;
        Pairing.G1Point[] IC;
    }

    struct Proof {
        Pairing.G1Point A;
        Pairing.G1Point A_p;
        Pairing.G2Point B;
        Pairing.G1Point B_p;
        Pairing.G1Point C;
        Pairing.G1Point C_p;
        Pairing.G1Point K;
        Pairing.G1Point H;
    }

    VerifyingKey verifyKey;

    // Constructor.  For of vk is:
    //    uint256[4] A,               (offset 00 - 0x00)
    //    uint256[2] B,               (offset 04 - 0x04)
    //    uint256[4] C,               (offset 06 - 0x06)
    //    uint256[4] gamma,           (offset 10 - 0x0a)
    //    uint256[2] gammaBeta1,      (offset 14 - 0x0e)
    //    uint256[4] gammaBeta2,      (offset 16 - 0x10)
    //    uint256[4] Z,               (offset 20 - 0x14)
    //    uint256[] IC_coefficients)  (offset 24 - 0x18) (2 words each)
    constructor(
        uint256 mk_depth,
        address token,
        uint256[] memory vk)
        BaseMixer(mk_depth, token) public {
        uint256 vk_words = vk.length;
        require(vk_words >= 26, "invalid vk length");

        verifyKey.A = Pairing.G2Point(vk[0], vk[1], vk[2], vk[3]);
        verifyKey.B = Pairing.G1Point(vk[4], vk[5]);
        verifyKey.C = Pairing.G2Point(vk[6], vk[7], vk[8], vk[9]);
        verifyKey.gamma = Pairing.G2Point(vk[10], vk[11], vk[12], vk[13]);
        verifyKey.gammaBeta1 = Pairing.G1Point(vk[14], vk[15]);
        verifyKey.gammaBeta2 = Pairing.G2Point(vk[16], vk[17], vk[18], vk[19]);
        verifyKey.Z = Pairing.G2Point(vk[20], vk[21], vk[22], vk[23]);

        for (uint256 i = 24; i < vk_words ; i += 2) {
            verifyKey.IC.push(Pairing.G1Point(vk[i], vk[i+1]));
        }
    }

    // This function allows to mix coins and execute payments in zero knowledge.
    // Nb of ciphertexts depends on the JS description (Here 2 inputs)
    function mix (
        uint256[2] memory a,
        uint256[2] memory a_p,
        uint256[4] memory b,
        uint256[2] memory b_p,
        uint256[2] memory c,
        uint256[2] memory c_p,
        uint256[2] memory h,
        uint256[2] memory k,
        uint256[4] memory vk,
        uint256 sigma,
        uint256[nbInputs] memory input,
        bytes32 pk_sender,
        bytes[jsOut] memory ciphertexts)
        public payable {

        // 1. Check the root and the nullifiers
        bytes32[jsIn] memory nullifiers;
        check_mkroot_nullifiers_hsig_append_nullifiers_state(
            vk, input, nullifiers);

        // 2.a Verify the signature on the hash of data_to_be_signed
        bytes32 hash_to_be_signed = sha256(
            abi.encodePacked(
                pk_sender,
                // Must be unrolled for now.
                ciphertexts[0],
                ciphertexts[1],
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
            OTSchnorrVerifier.verify(
                vk[0],
                vk[1],
                vk[2],
                vk[3],
                sigma,
                hash_to_be_signed
            ),
            "Invalid signature: Unable to verify the signature correctly"
        );

        // 2.b Verify the proof
        require(
            verifyTx(a, a_p, b, b_p, c, c_p, h, k, input),
            "Invalid proof: Unable to verify the proof correctly"
        );

        // 3. Append the commitments to the tree
        bytes32[jsOut] memory commitments;
        assemble_commitments_and_append_to_state(input, commitments);

        // 4. get the public values in Wei and modify the state depending on
        // their values
        process_public_values(input);

        // 5. Add the new root to the list of existing roots and emit it
        bytes32 new_merkle_root = recomputeRoot(jsOut);
        add_merkle_root(new_merkle_root);

        // Emit the all Mix data
        emit LogMix(
            new_merkle_root,
            nullifiers,
            pk_sender,
            commitments,
            ciphertexts);
    }

    function getIC(uint256 i) public view returns (uint) {
        return(verifyKey.IC[i].X);
    }

    function getICLen() public view returns (uint) {
        return(verifyKey.IC.length);
    }

    function verify(
        uint256[nbInputs] memory input,
        Proof memory proof)
        internal
        returns (uint) {
        VerifyingKey memory vk = verifyKey;
        // |I_{in}| == input.length, and vk.IC also contains A_0(s). Thus
        // ||vk.IC| == input.length + 1
        require(
            input.length + 1 == vk.IC.length,
            "Using strong input consistency, and the input length differs from expected"
        );

        // 1. Compute the linear combination
        //   vk_x := vk_{IC,0} + \sum_{i=1}^{n} x_i * vk_{IC,i}, vk_x ∈ G1
        //
        // E(A_{in}(s)) if the encoding of
        //   A_{in}(s) = \sum_{k ∈ I_{in}} a_k · A_k(s),
        // where I_{in} denotes the indices of the input wires.
        //
        // |I_{in}| = n here as we assume that we have a vector x of inputs of
        // size n.
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint256 i = 0; i < input.length; i++) {
            vk_x = Pairing.add(vk_x, Pairing.mul(vk.IC[i + 1], input[i]));
        }
        vk_x = Pairing.add(vk_x, vk.IC[0]);

        // 2. Check the validity of knowledge commitments for A, B, C
        //   e(π_A, vk_A) = e(π′A, P2), e(vk_B, π_B)
        //                = e(π′_B, P2), e(vk_C, π_C)
        //                = e(π′_C, P2),
        if (!Pairing.pairingProd2(
            proof.A, vk.A,
            Pairing.negate(proof.A_p), Pairing.P2())
        ) {
            return 1;
        }
        if (!Pairing.pairingProd2(
            vk.B, proof.B,
            Pairing.negate(proof.B_p), Pairing.P2())
        ) {
            return 2;
        }
        if (!Pairing.pairingProd2(
            proof.C, vk.C,
            Pairing.negate(proof.C_p), Pairing.P2())
        ) {
            return 3;
        }

        // 3. Check same coefficients were used
        // e(π_K, vk_γ) = e(vk_x + π_A + π_C, vk_{γβ2}) · e(vk_{γβ1}, π_B)
        if (!Pairing.pairingProd3(
                proof.K, vk.gamma,
                Pairing.negate(Pairing.add(vk_x, Pairing.add(proof.A, proof.C))), vk.gammaBeta2,
                Pairing.negate(vk.gammaBeta1), proof.B)
        ) {
            return 4;
        }

        // 4. Check QAP divisibility
        // e(vk_x + π_A, π_B) = e(π_H, vk_Z) · e(π_C, P2)
        if (!Pairing.pairingProd3(
                Pairing.add(vk_x, proof.A), proof.B,
                Pairing.negate(proof.H), vk.Z,
                Pairing.negate(proof.C), Pairing.P2())
        ) {
            return 5;
        }

        return 0;
    }

    function verifyTx(
        uint256[2] memory a,
        uint256[2] memory a_p,
        uint256[4] memory b,
        uint256[2] memory b_p,
        uint256[2] memory c,
        uint256[2] memory c_p,
        uint256[2] memory h,
        uint256[2] memory k,
        uint256[nbInputs] memory primaryInputs)
        public
        returns (bool) {
        // Scalar field characteristic
        // solium-disable-next-line
        uint256 r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.A_p = Pairing.G1Point(a_p[0], a_p[1]);
        proof.B = Pairing.G2Point(b[0], b[1], b[2], b[3]);
        proof.B_p = Pairing.G1Point(b_p[0], b_p[1]);
        proof.C = Pairing.G1Point(c[0], c[1]);
        proof.C_p = Pairing.G1Point(c_p[0], c_p[1]);
        proof.H = Pairing.G1Point(h[0], h[1]);
        proof.K = Pairing.G1Point(k[0], k[1]);

        // uint256[] memory inputValues = new uint256[](primaryInputs.length);
        for(uint256 i = 0; i < primaryInputs.length; i++){
            // Make sure that all primary inputs lie in the scalar field
            require(
                primaryInputs[i] < r,
                "Input is not is scalar field"
            );
            /* inputValues[i] = primaryInputs[i]; */
        }

        uint256 verification_result = verify(primaryInputs, proof);
        if (verification_result != 0) {
            /* emit LogVerifier("Failed to verify the transaction"); */
            return false;
        }

        /* emit LogVerifier("Proof verification successfull"); */
        return true;
    }
}
