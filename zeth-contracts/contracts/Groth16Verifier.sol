// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

/*
 * Reference paper:
 *
 * \[Gro16]:
 * "On the Size of Pairing-based Non-interactive Arguments",
 * Jens Groth,
 * EUROCRYPT 2016,
 * <https://eprint.iacr.org/2016/260>
**/

import "./Pairing.sol";

// Groth16 Verifier contract
contract Groth16Verifier {
    using Pairing for *;

    // The structure of the verification key differs from the reference paper.
    // It doesn't contain any element of GT, but only elements of G1 and G2 (the
    // source groups). This is due to the lack of precompiled contract to
    // manipulate elements of the target group GT on Ethereum.
    struct VerifyingKey {
        Pairing.G1Point Alpha;      // slots 0x00, 0x01
        Pairing.G2Point Beta;       // slots 0x02, 0x03, 0x04, 0x05
        Pairing.G2Point Delta;      // slots 0x06, 0x07, 0x08, 0x09
        Pairing.G1Point[] ABC;      // slot 0x0a
    }

    // Internal Proof structure.  Avoids reusing the G1 and G2 structs, since
    // these cause extra pointers in memory, and complexity passing the data to
    // precompiled contracts.
    struct Proof {
        // Pairing.G1Point A;
        uint A_X;
        uint A_Y;
        // Pairing.G2Point B;
        uint B_X0;
        uint B_X1;
        uint B_Y0;
        uint B_Y1;
        // Pairing.G1Point C;
        uint C_X;
        uint C_Y;
    }

    VerifyingKey verifyKey;

    event LogVerifier(string);

    constructor(
        uint[2] memory Alpha,
        uint[2] memory Beta1,
        uint[2] memory Beta2,
        uint[2] memory Delta1,
        uint[2] memory Delta2,
        uint[] memory ABC_coords
    ) public {
        verifyKey.Alpha = Pairing.G1Point(Alpha[0], Alpha[1]);
        verifyKey.Beta = Pairing.G2Point(Beta1[0], Beta1[1], Beta2[0], Beta2[1]);
        verifyKey.Delta = Pairing.G2Point(
            Delta1[0], Delta1[1], Delta2[0], Delta2[1]);

        // The `ABC` are elements of G1 (and thus have 2 coordinates in the
        // underlying field). Here, we reconstruct these group elements from
        // field elements (ABC_coords are field elements)
        uint i;
        while(verifyKey.ABC.length != ABC_coords.length/2) {
            verifyKey.ABC.push(Pairing.G1Point(ABC_coords[i], ABC_coords[i+1]));
            i += 2;
        }
    }

    function verify(uint[] memory input, Proof memory proof) internal returns (uint) {
        VerifyingKey memory vk = verifyKey;

        // `input.length` = size of the instance = l (see notations in the reference paper)
        // We have coefficients indexed in the range[1..l], where l is the instance size, and we define
        // a_0 = 1. This is the reason why we need to check that:
        // input.length + 1 == vk.ABC.length (the +1 accounts for a_0)
        // This equality is a strong consistency check (len(givenInputs) needs to equal expectedInputSize (not less))
        require(
            input.length + 1 == vk.ABC.length,
            "Using strong input consistency, and the input length differs from expected"
        );

        // 1. Compute the linear combination vk_x = \sum_{i=0}^{l} a_i * vk.ABC[i], vk_x in G1
        Pairing.G1Point memory vk_x = vk.ABC[0]; // a_0 = 1
        for (uint i; i < input.length; i++) {
            vk_x = Pairing.add(vk_x, Pairing.mul(vk.ABC[i + 1], input[i]));
        }

        // 2. The verification check:
        // e(Proof.A, Proof.B) = e(vk.Alpha, vk.Beta) * e(vk_x, P2) * e(Proof.C, vk.Delta)
        // where:
        // - e: G_1 x G_2 -> G_T is a bilinear map
        // - `*`: denote the group operation in G_T

        bool res = Pairing.pairingProd4(
            Pairing.negate(Pairing.G1Point(proof.A_X, proof.A_Y)),
            Pairing.G2Point(proof.B_X0, proof.B_X1, proof.B_Y0, proof.B_Y1),
            verifyKey.Alpha, verifyKey.Beta,
            vk_x, Pairing.P2(),
            Pairing.G1Point(proof.C_X, proof.C_Y),
            verifyKey.Delta
        );

        if (!res) {
            return 0;
        }

        return 1;
    }

    function verifyTx(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[] memory primaryInputs
    ) public returns (bool) {
        // Scalar field characteristic
        uint256 r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

        Proof memory proof;
        proof.A_X = a[0];
        proof.A_Y = a[1];
        proof.B_X0 = b[0][0];
        proof.B_X1 = b[0][1];
        proof.B_Y0 = b[1][0];
        proof.B_Y1 = b[1][1];
        proof.C_X = c[0];
        proof.C_Y = c[1];

        uint[] memory inputValues = new uint[](primaryInputs.length);
        for(uint i = 0; i < primaryInputs.length; i++){
            // Make sure that all primary inputs lie in the scalar field
            require(
                primaryInputs[i] < r,
                "Input is not in scalar field"
            );
            inputValues[i] = primaryInputs[i];
        }

        uint verification_result = verify(inputValues, proof);
        if (verification_result != 1) {
            emit LogVerifier("Failed to verify the transaction");
            return false;
        }

        emit LogVerifier("Proof verification successfull");
        return true;
    }
}
