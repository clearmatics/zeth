// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./LPairing.sol";
import "./BaseMixerAltBN128.sol";

contract MixerAltBN128Pghr13 is BaseMixerAltBN128
{
    struct VerifyingKey {
        LPairing.G2Point A;
        LPairing.G1Point B;
        LPairing.G2Point C;
        LPairing.G2Point gamma;
        LPairing.G1Point gammaBeta1;
        LPairing.G2Point gammaBeta2;
        LPairing.G2Point Z;
        LPairing.G1Point[] IC;
    }

    struct Proof {
        LPairing.G1Point A;
        LPairing.G1Point A_p;
        LPairing.G2Point B;
        LPairing.G1Point B_p;
        LPairing.G1Point C;
        LPairing.G1Point C_p;
        LPairing.G1Point K;
        LPairing.G1Point H;
    }

    constructor(
        uint256 mkDepth,
        address token,
        uint256[] memory vk,
        address permittedDispatcher,
        uint256[2] memory vkHash
    )
        BaseMixerAltBN128(mkDepth, token, vk, permittedDispatcher, vkHash)
    {
        uint256 vk_words = vk.length;
        require(vk_words >= 26, "invalid vk length");
    }

    function _verify(
        uint256[] memory inputs,
        Proof memory proof
    )
        internal
        returns (uint)
    {

        // Decode _vk into a VerifyKey struct
        uint256 vk_words = _vk.length;
        require(vk_words >= 26, "invalid vk length");
        uint256 ic_length = (vk_words - 24) / 2;

        VerifyingKey memory vk;
        vk.IC = new LPairing.G1Point[](ic_length);
        vk.A = LPairing.G2Point(_vk[0], _vk[1], _vk[2], _vk[3]);
        vk.B = LPairing.G1Point(_vk[4], _vk[5]);
        vk.C = LPairing.G2Point(_vk[6], _vk[7], _vk[8], _vk[9]);
        vk.gamma = LPairing.G2Point(_vk[10], _vk[11], _vk[12], _vk[13]);
        vk.gammaBeta1 = LPairing.G1Point(_vk[14], _vk[15]);
        vk.gammaBeta2 = LPairing.G2Point(_vk[16], _vk[17], _vk[18], _vk[19]);
        vk.Z = LPairing.G2Point(_vk[20], _vk[21], _vk[22], _vk[23]);
        for (uint256 i = 24; i < vk_words ; i += 2) {
            vk.IC[(i-24)/2] = LPairing.G1Point(_vk[i], _vk[i+1]);
        }

        // |I_{in}| == input.length, and vk.IC also contains A_0(s). Thus
        // ||vk.IC| == input.length + 1
        require(
            inputs.length + 1 == vk.IC.length,
            "Using strong input consistency, and the input length differs from"
            " expected"
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
        LPairing.G1Point memory vk_x = LPairing.G1Point(0, 0);
        for (uint256 i = 0; i < inputs.length; i++) {
            vk_x = LPairing._addG1(vk_x,
                LPairing._scalarMulG1(vk.IC[i + 1], inputs[i]));
        }
        vk_x = LPairing._addG1(vk_x, vk.IC[0]);

        // 2. Check the validity of knowledge commitments for A, B, C
        //   e(π_A, vk_A) = e(π′A, _genG2), e(vk_B, π_B)
        //                = e(π′_B, _genG2), e(vk_C, π_C)
        //                = e(π′_C, _genG2),
        if (!LPairing._pairingProd2(
            proof.A, vk.A,
            LPairing._negateG2(proof.A_p), LPairing._genG2())
        ) {
            return 1;
        }
        if (!LPairing._pairingProd2(
            vk.B, proof.B,
            LPairing._negateG2(proof.B_p), LPairing._genG2())
        ) {
            return 2;
        }
        if (!LPairing._pairingProd2(
            proof.C, vk.C,
            LPairing._negateG2(proof.C_p), LPairing._genG2())
        ) {
            return 3;
        }

        // 3. Check same coefficients were used
        // e(π_K, vk_γ) = e(vk_x + π_A + π_C, vk_{γβ2}) · e(vk_{γβ1}, π_B)

        bool pairing_check = LPairing._pairingProd3(
            proof.K,
            vk.gamma,
            LPairing._negateG2(LPairing._addG1(vk_x,
                LPairing._addG1(proof.A, proof.C))),
            vk.gammaBeta2,
            LPairing._negateG2(vk.gammaBeta1),
            proof.B);
        if (!pairing_check) {
            return 4;
        }

        // 4. Check QAP divisibility
        // e(vk_x + π_A, π_B) = e(π_H, vk_Z) · e(π_C, _genG2)
        pairing_check = LPairing._pairingProd3(
            LPairing._addG1(vk_x, proof.A),
            proof.B,
            LPairing._negateG2(proof.H),
            vk.Z,
            LPairing._negateG2(proof.C),
            LPairing._genG2());
        if (!pairing_check) {
            return 5;
        }

        return 0;
    }

    function _verifyZkProof(
        uint256[] memory proofData,
        uint256 publicInputsHash
    )
        internal
        override
        returns (bool)
    {
        // Scalar field characteristic
        // solhint-disable-next-line
        uint256 r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

        // Slightly redundant
        Proof memory proof;
        proof.A = LPairing.G1Point(proofData[0], proofData[1]);
        proof.A_p = LPairing.G1Point(proofData[2], proofData[3]);
        proof.B = LPairing.G2Point(
            proofData[4], proofData[5], proofData[6], proofData[7]);
        proof.B_p = LPairing.G1Point(proofData[8], proofData[9]);
        proof.C = LPairing.G1Point(proofData[10], proofData[11]);
        proof.C_p = LPairing.G1Point(proofData[12], proofData[13]);
        proof.H = LPairing.G1Point(proofData[14], proofData[15]);
        proof.K = LPairing.G1Point(proofData[16], proofData[17]);

        require(
            publicInputsHash < r,
            "Input is not is scalar field"
        );

        uint256[] memory inputs = new uint256[](1);
        inputs[0] = publicInputsHash;
        uint256 verification_result = _verify(inputs, proof);
        if (verification_result != 0) {
            return false;
        }

        return true;
    }
}
