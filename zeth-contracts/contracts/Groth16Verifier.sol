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
contract Verifier {
    using Pairing for *;

    struct VerifyingKey {
        Pairing.GTPoint AB;
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
        uint[3][2] memory AB1,
        uint[3][2] memory AB2,
        uint[2] memory Gamma1,
        uint[2] memory Gamma2,
        uint[2] memory Delta1,
        uint[2] memory Delta2,
        uint[] memory Gamma_ABC_elements
    ) public {
        verifyKey.AB = Pairing.GTPoint(AB1, AB2);//TODO not sure if it works
        verifyKey.Gamma = Pairing.G2Point(Gamma1, Gamma2);
        verifyKey.Delta = Pairing.G2Point(Delta1, Delta2);
        
        uint i = 0;
        while(verifyKey.Gamma_ABC.length != Gamma_ABC_elements.length/2) {
            verifyKey.Gamma_ABC.push(Pairing.G1Point(Gamma_ABC_elements[i], Gamma_ABC_elements[i+1]));
            i += 2;
        }
    }

    function getIC(uint i) public view returns (uint) {//TODO: do I need it?
        //TODO
    }

    function getICLen() public view returns (uint) {//TODO: do I need it?
        //TODO
    }

    function verify(uint[] memory input, Proof memory proof) internal returns (uint) {
        VerifyingKey memory vk = verifyKey;

        y_side_1 = (Pairing.negate(g_alpha), g2_beta);//TODO fix this
        y_side_2 = 2;//TODO;

        bool res = !Pairing.pairingProd4(
            proof.A,proof.B, 
            y_side_1, 
            y_side_2, 
            Pairing.negate(proof.C), Pairing.G2(vk.Delta1, vk.Delta2));
        if(!res){
            return 1;
        }
        return 0;

    }

    function verifyTx(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory b_p,
        uint[2] memory c,
        uint[2] memory c_p,
        uint[2] memory h,
        uint[2] memory k,
        uint[] memory primaryInputs
    ) public returns (bool) {
        //TODO
    }
}
