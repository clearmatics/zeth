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

// BCTV14 Verifier contract
contract Verifier {
    using Pairing for *;

    struct VerifyingKey {
        //TODO
    }

    struct Proof {
        //TODO
    }

    VerifyingKey verifyKey;

    event LogVerifier(string);

    constructor(
        //TODO
    ) public {
        //TODO
    }

    function getIC(uint i) public view returns (uint) {
        //TODO
    }

    function getICLen() public view returns (uint) {
        //TODO
    }

    function verify(uint[] memory input, Proof memory proof) internal returns (uint) {
        //TODO
    }

    function verifyTx(
        //TODO
    ) public returns (bool) {
        //TODO
    }
}
