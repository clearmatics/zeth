pragma solidity ^0.5.0;

import "./MerkleTreeSha256.sol";
import "./Groth16Verifier.sol";
import "./Bytes.sol";
import "./Mixer.sol";

/*
 * Note1:
 * We might want to use the `Szabo` as a unit for the payments.
 * In fact, as we are using hex strings of length 64bits in the prover to handle the values,
 * the max value we can encode is: "0xFFFFFFFFFFFFFFFF" which corresponds to:
 * "18446744073709551615". If we use this number as WEI, this represents:
 * "18.446744073709551615" ETH. Here we clearly see that we do not as many digits after the
 * floating point, and moreover, we would like to be able to do payments of more than
 * 18ETH. If we use the number "18446744073709551615" (our max) as Szabo, we can make payments
 * up to "18446744073709.551615" ETH which presents a sufficiently high upper bound and which contains
 * 6 digits after the floating point.
 * Here we assume that this is sufficient for our use cases.
 *
 * It is possible to adjust by changing the way the max number "18446744073709551615" is interpreted
 * (changing the unit)
 * See: https://solidity.readthedocs.io/en/v0.4.21/units-and-global-variables.html#ether-units
**/

/*
 * Note2: Because we emit the ciphertexts and the addresses of insertion of the commitments in the tree in the same
 * tx, we have a great way for the recipient to accelerate the verification of a payment.
 * In fact:
 * If Alice receives a payment, then she has the decryption key to retrieve the plaintext of an encrypted note that is emitted in the
 * call of the `transfer`. However, in the same smart contract call are emitted the addresses of insertion of the commitments
 * in the merkle tree. This means that the recipient does not need to verify that the re-computed commitment is "somewhere" in the set of the merkle tree leaves.
 * Instead the recipient JUST has to verify that the recomputed commitment is one of the commitment in the address set that is emitted during the smart contract call.
 * This makes it easier to check the validity of a payment, and is much faster to verify as we directly tell the recipient "where to look for his commitment in the tree".
 * By leveraging this data, we avoid a lot of unecessary overhead just to confirm a payment here.
**/

contract Pghr13Mixer is Mixer {
    using Bytes for *;

    // Smart contract responsible of on-chain verification of proofs
    Verifier public _zksnark_verifier;

    // Constructor
    constructor(address _zksnark_verify, uint depth, address token) Mixer (depth, token) public {
        _zksnark_verifier = Verifier(_zksnark_verify);
    }

    // This function allows to mix coins and execute payments in zero knowledge
    function mix (
        //TODO
    ) public payable {
        //TODO
    }
}
