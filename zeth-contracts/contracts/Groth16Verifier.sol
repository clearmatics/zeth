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
    // It doesn't contain any element of GT, but only elements of G1 and G2 (the source groups).
    // This is due to the lack of precompiled contract to manipulate elements of the target group GT on Ethereum.
    struct VerifyingKey {
        Pairing.G1Point Alpha; // element of G1 used to obtain AlphaBeta in GT
        Pairing.G2Point Beta; // element of G2 used to obtain AlphaBeta in GT
        Pairing.G2Point Gamma;
        Pairing.G2Point Delta;
        Pairing.G1Point[] Gamma_ABC; // List of encodings of [Beta * u_i(x) + Alpha * v_i(x) + w_i(x)] / Gamma, for i in [0..l], in G1
    }

    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }

    VerifyingKey verifyKey;

    event LogVerifier(string);

    constructor(
        uint[2] memory Alpha,
        uint[2] memory Beta1,
        uint[2] memory Beta2,
        uint[2] memory Gamma1,
        uint[2] memory Gamma2,
        uint[2] memory Delta1,
        uint[2] memory Delta2,
        uint[] memory Gamma_ABC_coords
    ) public {
        verifyKey.Alpha = Pairing.G1Point(Alpha[0], Alpha[1]);
        verifyKey.Beta = Pairing.G2Point(Beta1, Beta2);
        verifyKey.Gamma = Pairing.G2Point(Gamma1, Gamma2);
        verifyKey.Delta = Pairing.G2Point(Delta1, Delta2);

        // The `Gamma_ABC` are elements of G1 (and thus have 2 coordinates in the underlying field)
        // Here, we reconstruct these group elements from field elements (Gamma_ABC_coords are field elements)
        uint i = 0;
        while(verifyKey.Gamma_ABC.length != Gamma_ABC_coords.length/2) {
            verifyKey.Gamma_ABC.push(Pairing.G1Point(Gamma_ABC_coords[i], Gamma_ABC_coords[i+1]));
            i += 2;
        }
    }

    function verify(uint[] memory input, Proof memory proof) internal returns (uint) {
        VerifyingKey memory vk = verifyKey;

        // `input.length` = size of the instance = l (see notations in the reference paper)
        // We have coefficients indexed in the range[1..l], where l is the instance size, and we define
        // a_0 = 1. This is the reason why we need to check that:
        // input.length + 1 == vk.Gamma_ABC.length (the +1 accounts for a_0)
        // This equality is a strong consistency check (len(givenInputs) needs to equal expectedInputSize (not less))
        require(
            input.length + 1 == vk.Gamma_ABC.length,
            "Using strong input consistency, and the input length differs from expected"
        );

        // 1. Compute the linear combination vk_x = \sum_{i=0}^{l} a_i * vk.Gamma_ABC[i], vk_x in G1
        Pairing.G1Point memory vk_x = vk.Gamma_ABC[0]; // a_0 = 1
        for (uint i = 0; i < input.length; i++) {
            vk_x = Pairing.add(vk_x, Pairing.mul(vk.Gamma_ABC[i + 1], input[i]));
        }

        // 2. The verification check:
        // e(Proof.A, Proof.B) = e(vk.Alpha, vk.Beta) * e(vk_x, vk.Gamma) * e(Proof.C, vk.Delta)
        // where:
        // - e: G_1 x G_2 -> G_T is a bilinear map
        // - `*`: denote the group operation in G_T
        bool res = Pairing.pairingProd4(
            proof.A, proof.B,
            Pairing.negate(vk.Alpha), vk.Beta,
            Pairing.negate(vk_x), vk.Gamma,
            Pairing.negate(proof.C), vk.Delta
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
        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);

        uint[] memory inputValues = new uint[](primaryInputs.length);
        for(uint i = 0; i < primaryInputs.length; i++){
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
