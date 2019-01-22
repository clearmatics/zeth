pragma solidity ^0.5.0;

import "./MerkleTreeSha256.sol";
import "./Verifier.sol";
import "./Bytes.sol";

contract Miximus is MerkleTreeSha256 {
    using Bytes for *;

    // The roots of the different updated trees
    mapping(bytes32 => bool) roots;

    // The public list of nullifiers (prevents double spend)
    mapping(bytes32 => bool) nullifiers;

    // Constructor
    constructor(uint depth) MerkleTreeSha256(depth) public {
        // Nothing
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

    // Deposit takes a commitment as a parameter. The commitment in inserted in the Merkle Tree of commitment
    // in exchange of an amount of ether (the mixer's denomination) being paid
    function deposit(
        string memory ciphertext,
        bytes32 commitment,
        bytes32 internal_commitment_k, // Added to support minting of arbitrary values
        bytes32 trapdoor_s // Added to support minting of arbitrary values
    ) public payable {
        // Verify that the value the depositer commited to is the same as the value paid during the function call
        // Recompute the commitment from the value, the internal_commitment_k, and the trapdoor_s
        bytes32 recomputed_commitment = sha256(abi.encodePacked(trapdoor_s, internal_commitment_k, msg.value));
        require(
            recomputed_commitment == commitment,
            "Wrong msg.value: Should equal the value commited to"
        );

        uint commitmentAddress = insert(commitment);
        emit LogAddress(commitmentAddress);

        bytes32 currentRoot = getRoot();
        emit LogMerkleRoot(currentRoot);

        // Emit the coin's secret data encrypted with the recipient's key
        emit LogSecretCiphers(ciphertext);

        roots[currentRoot] = true;
    }
}
