pragma solidity ^0.5.0;

/*
 * Reference papers:
 * \[PGHR13]:
 * "Pinocchio: Nearly practical verifiable computation",
 * Bryan Parno, Craig Gentry, Jon Howell, Mariana Raykova,
 * IEEE S&P 2013,
 * <https://eprint.iacr.org/2013/279>
 *
 * [BCTV14]:
 * "Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture",
 * Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, Madars Virza,
 * USENIX Security 2014,
 * <http://eprint.iacr.org/2013/879>
 *
 * [Gab19]
 * "On the security of the BCTV Pinocchio zk-SNARK variant",
 * Ariel Gabizon,
 * <https://eprint.iacr.org/2019/119.pdf>
**/

import "./Pairing.sol";

// PGHR13 Verifier contract
contract Pghr13Verifier {
    using Pairing for *;

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

    event LogVerifier(string);

    constructor(
        uint[2] memory A1,
        uint[2] memory A2,
        uint[2] memory B,
        uint[2] memory C1,
        uint[2] memory C2,
        uint[2] memory gamma1,
        uint[2] memory gamma2,
        uint[2] memory gammaBeta1,
        uint[2] memory gammaBeta2_1,
        uint[2] memory gammaBeta2_2,
        uint[2] memory Z1,
        uint[2] memory Z2,
        uint[] memory IC_coefficients
    ) public {
        verifyKey.A = Pairing.G2Point(A1,A2);
        verifyKey.B = Pairing.G1Point(B[0], B[1]);
        verifyKey.C = Pairing.G2Point(C1, C2);
        verifyKey.gamma = Pairing.G2Point(gamma1, gamma2);
        verifyKey.gammaBeta1 = Pairing.G1Point(gammaBeta1[0], gammaBeta1[1]);
        verifyKey.gammaBeta2 = Pairing.G2Point(gammaBeta2_1, gammaBeta2_2);
        verifyKey.Z = Pairing.G2Point(Z1,Z2);

        uint i = 0;
        while(verifyKey.IC.length != IC_coefficients.length/2) {
            verifyKey.IC.push(Pairing.G1Point(IC_coefficients[i], IC_coefficients[i+1]));
            i += 2;
        }
    }

    function getIC(uint i) public view returns (uint) {
        return(verifyKey.IC[i].X);
    }

    function getICLen() public view returns (uint) {
        return(verifyKey.IC.length);
    }

    function verify(uint[] memory input, Proof memory proof) internal returns (uint) {
        VerifyingKey memory vk = verifyKey;
        // |I_{in}| == input.length, and vk.IC also contains A_0(s). Thus |vk.IC| == input.length + 1
        require(
            input.length + 1 == vk.IC.length,
            "Using strong input consistency, and the input length differs from expected"
        );

        // 1. Compute the linear combination vk_x := vk_{IC,0} + \sum_{i=1}^{n} x_i * vk_{IC,i}, vk_x ∈ G1
        // E(A_{in}(s)) if the encoding of A_{in}(s) = \sum_{k ∈ I_{in}} a_k · A_k(s), where I_{in} denotes the indices of the input wires
        // |I_{in}| = n here as we assume that we have a vector x of inputs of size n
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            vk_x = Pairing.add(vk_x, Pairing.mul(vk.IC[i + 1], input[i]));
        }
        vk_x = Pairing.add(vk_x, vk.IC[0]);

        // 2. Check the validity of knowledge commitments for A, B, C
        // e(π_A, vk_A) = e(π′A, P2), e(vk_B, π_B) = e(π′_B, P2), e(vk_C, π_C) = e(π′_C, P2),
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
        uint[2] memory a,
        uint[2] memory a_p,
        uint[2][2] memory b,
        uint[2] memory b_p,
        uint[2] memory c,
        uint[2] memory c_p,
        uint[2] memory h,
        uint[2] memory k,
        uint[] memory primaryInputs
    ) public returns (bool) {
        // Scalar field characteristic
        uint256 r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.A_p = Pairing.G1Point(a_p[0], a_p[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.B_p = Pairing.G1Point(b_p[0], b_p[1]);
        proof.C = Pairing.G1Point(c[0], c[1]);
        proof.C_p = Pairing.G1Point(c_p[0], c_p[1]);
        proof.H = Pairing.G1Point(h[0], h[1]);
        proof.K = Pairing.G1Point(k[0], k[1]);

        uint[] memory inputValues = new uint[](primaryInputs.length);
        for(uint i = 0; i < primaryInputs.length; i++){
            // Make sure that all primary inputs lie in the scalar field
            require(
                primaryInputs[i] < r,
                "Input is not a scalar field"
            );
            inputValues[i] = primaryInputs[i];
        }

        uint verification_result = verify(inputValues, proof);
        if (verification_result != 0) {
            emit LogVerifier("Failed to verify the transaction");
            return false;
        }

        emit LogVerifier("Proof verification successfull");
        return true;
    }
}
