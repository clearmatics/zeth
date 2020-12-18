// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

import "./Pairing.sol";
import "./AltBN128MixerBase.sol";

contract Pghr13AltBN128Mixer is AltBN128MixerBase
{
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

    constructor(
        uint256 mk_depth,
        address token,
        uint256[] memory vk
    )
        public
        AltBN128MixerBase(mk_depth, token, vk)
    {
        uint256 vk_words = vk.length;
        require(vk_words >= 26, "invalid vk length");
    }

    function verify(
        uint256[num_inputs] memory input,
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
        vk.IC = new Pairing.G1Point[](ic_length);
        vk.A = Pairing.G2Point(_vk[0], _vk[1], _vk[2], _vk[3]);
        vk.B = Pairing.G1Point(_vk[4], _vk[5]);
        vk.C = Pairing.G2Point(_vk[6], _vk[7], _vk[8], _vk[9]);
        vk.gamma = Pairing.G2Point(_vk[10], _vk[11], _vk[12], _vk[13]);
        vk.gammaBeta1 = Pairing.G1Point(_vk[14], _vk[15]);
        vk.gammaBeta2 = Pairing.G2Point(_vk[16], _vk[17], _vk[18], _vk[19]);
        vk.Z = Pairing.G2Point(_vk[20], _vk[21], _vk[22], _vk[23]);
        for (uint256 i = 24; i < vk_words ; i += 2) {
            vk.IC[(i-24)/2] = Pairing.G1Point(_vk[i], _vk[i+1]);
        }

        // |I_{in}| == input.length, and vk.IC also contains A_0(s). Thus
        // ||vk.IC| == input.length + 1
        require(
            input.length + 1 == vk.IC.length,
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

        bool pairing_check = Pairing.pairingProd3(
            proof.K,
            vk.gamma,
            Pairing.negate(Pairing.add(vk_x, Pairing.add(proof.A, proof.C))),
            vk.gammaBeta2,
            Pairing.negate(vk.gammaBeta1),
            proof.B);
        if (!pairing_check) {
            return 4;
        }

        // 4. Check QAP divisibility
        // e(vk_x + π_A, π_B) = e(π_H, vk_Z) · e(π_C, P2)
        pairing_check = Pairing.pairingProd3(
            Pairing.add(vk_x, proof.A),
            proof.B,
            Pairing.negate(proof.H),
            vk.Z,
            Pairing.negate(proof.C),
            Pairing.P2());
        if (!pairing_check) {
            return 5;
        }

        return 0;
    }

    function verify_zk_proof(
        uint256[] memory proof_data,
        uint256[num_inputs] memory inputs
    )
        internal
        returns (bool)
    {
        // Scalar field characteristic
        // solhint-disable-next-line
        uint256 r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

        // Slightly redundant
        Proof memory proof;
        proof.A = Pairing.G1Point(proof_data[0], proof_data[1]);
        proof.A_p = Pairing.G1Point(proof_data[2], proof_data[3]);
        proof.B = Pairing.G2Point(
            proof_data[4], proof_data[5], proof_data[6], proof_data[7]);
        proof.B_p = Pairing.G1Point(proof_data[8], proof_data[9]);
        proof.C = Pairing.G1Point(proof_data[10], proof_data[11]);
        proof.C_p = Pairing.G1Point(proof_data[12], proof_data[13]);
        proof.H = Pairing.G1Point(proof_data[14], proof_data[15]);
        proof.K = Pairing.G1Point(proof_data[16], proof_data[17]);

        for(uint256 i = 0; i < inputs.length; i++){
            // Make sure that all primary inputs lie in the scalar field
            require(
                inputs[i] < r,
                "Input is not is scalar field"
            );
        }

        uint256 verification_result = verify(inputs, proof);
        if (verification_result != 0) {
            return false;
        }

        return true;
    }
}
