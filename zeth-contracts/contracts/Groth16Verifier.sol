pragma solidity ^0.5.0;

/*
 * Reference papers:
 *
 * [BCTV14]:
 * "Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture",
 * Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, Madars Virza,
 * USENIX Security 2014,
 * <http://eprint.iacr.org/2013/879>
 *
 *\[Gro16]:
 *"On the Size of Pairing-based Non-interactive Arguments",
 *Jens Groth,
 *EUROCRYPT 2016,
 *<https://eprint.iacr.org/2016/260>
**/

import "./Pairing.sol";

// Groth16 Verifier contract
contract Groth16Verifier {
    using Pairing for *;

    struct VerifyingKey {
        Pairing.G1Point Alpha;
        Pairing.G2Point Beta;
        Pairing.G2Point Gamma;
        Pairing.G2Point Delta;
        Pairing.G1Point[] Gamma_ABC;
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
        uint[] memory Gamma_ABC_elements
    ) public {
        verifyKey.Alpha = Pairing.G1Point(Alpha[0], Alpha[1]);
        verifyKey.Beta = Pairing.G2Point(Beta1, Beta2);
        verifyKey.Gamma = Pairing.G2Point(Gamma1, Gamma2);
        verifyKey.Delta = Pairing.G2Point(Delta1, Delta2);
        
        uint i = 0;
        while(verifyKey.Gamma_ABC.length != Gamma_ABC_elements.length/2) {
            verifyKey.Gamma_ABC.push(Pairing.G1Point(Gamma_ABC_elements[i], Gamma_ABC_elements[i+1]));
            i += 2;
        }
    }

    function verify(uint[] memory input, Proof memory proof) internal returns (uint) {
        VerifyingKey memory vk = verifyKey;

        require(
            input.length + 1 == vk.Gamma_ABC.length,
            "Using strong input consistency, and the input length differs from expected"
        );

        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            vk_x = Pairing.add(vk_x, Pairing.mul(vk.Gamma_ABC[i + 1], input[i]));
        }
        vk_x = Pairing.add(vk_x, vk.Gamma_ABC[0]);

        bool res = Pairing.pairingProd4(
            proof.A,proof.B,
            Pairing.negate(vk.Alpha), vk.Beta, 
            Pairing.negate(vk_x), vk.Gamma, 
            Pairing.negate(proof.C), vk.Delta);

        if(!res){
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
