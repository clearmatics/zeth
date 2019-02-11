pragma solidity ^0.5.0;

import "./Verifier.sol";
import "./Bytes.sol";

contract WrapperVerifier {
    using Bytes for *;

    // The roots of the different updated trees
    mapping(bytes32 => bool) roots;

    // The public list of nullifiers (prevents double spend)
    mapping(bytes32 => bool) nullifiers;

    Verifier public zksnark_verifier;

    // Constructor
    constructor(address _zksnark_verify) public {
        zksnark_verifier = Verifier(_zksnark_verify);
    }

    // Event to emit the address of a commitment in the merke tree
    event LogAddress(uint commAddr);

    // Event to emit the merkle root of a tree
    event LogMerkleRoot(bytes32 root);

    // Event to emit the ciphertexts of the coins' data to be sent to the recipient of the payment
    // This event is key to obfuscate the tranaction graph while enabling on-chain storage of the coins' data
    // (useful to ease backup of user's wallets)
    event LogSecretCiphers(string ciphertext);

    // Debug only
    event LogRecomputedCommmitment(bytes32 recompComm);
    event LogTrapdoorS(bytes32 trap);
    event LogInternalCommitment(bytes32 interComm);
    event LogValue(uint256 value);
    event LogABIEncoded(bytes encoded);

    event LogDebug(string text);

    function verify(
        uint[2] memory a,
        uint[2] memory a_p,
        uint[2][2] memory b,
        uint[2] memory b_p,
        uint[2] memory c,
        uint[2] memory c_p,
        uint[2] memory h,
        uint[2] memory k,
        uint[] memory input
    ) public {
        require(
            zksnark_verifier.verifyTx(a, a_p, b, b_p, c, c_p, h, k, input),
            "Invalid proof: Unable to verify the proof correctly"
        );

        emit LogDebug("Worked!!");
    }
}
