pragma solidity ^0.5.0;

import "./MerkleTreeSha256.sol";
import "./Verifier.sol";
import "./Bytes.sol";

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

contract Mixer is MerkleTreeSha256 {
    using Bytes for *;

    // The roots of the different updated trees
    mapping(bytes32 => bool) roots;

    // The public list of nullifiers (prevents double spend)
    mapping(bytes32 => bool) nullifiers;

    // Smart contract responsible of on-chain verification of proofs
    Verifier public zksnark_verifier;

    // JoinSplit description, gives upper bound on number of inputs(nullifiers) and outputs(commitments/ciphertexts) to receive and process
    // IMPORTANT NOTE: We need to employ the same JS configuration than the one used in the cpp prover
    // 2-2 JoinSplit (used as a upper bound in the array of ciphertexts) -- Need to match with the JSDesc used in the circuit
    uint constant jsIn = 2;
    // 2-2 JoinSplit (used as a upper bound in the array of ciphertexts) -- Need to match with the JSDesc used in the circuit
    uint constant jsOut = 2;
    // We have 2 field elements for each digest (root, nullifiers, commitments) and 1 + 1 public values
    uint constant nbInputs = 2 * (1 + jsIn + jsOut) + 1 + 1;

    // Event to emit the address of a commitment in the merke tree
    event LogAddress(uint commAddr);

    // Event to emit the merkle root of a tree
    event LogMerkleRoot(bytes32 root);

    // Event to emit the ciphertexts of the coins' data to be sent to the recipient of the payment
    // This event is key to obfuscate the tranaction graph while enabling on-chain storage of the coins' data
    // (useful to ease backup of user's wallets)
    event LogSecretCiphers(string ciphertext);

    // Debug only
    event LogDebug(string message);

    // Constructor
    constructor(address _zksnark_verify, uint depth) MerkleTreeSha256(depth) public {
        zksnark_verifier = Verifier(_zksnark_verify);
        
        // We log the first root to get started
        bytes32 initialRoot = getRoot();
        roots[initialRoot] = true;
        emit LogMerkleRoot(initialRoot);
    }

    // This function allows to mix coins and execute payments in zero knowledge
    function mix (
        //string[jsIn] memory ciphertext, // Array of strings is a 2D array and is not supported
        string memory ciphertext1,
        string memory ciphertext2, // Nb of ciphertexts depends on the JS description (Here 2 inputs)
        uint[2] memory a,
        uint[2] memory a_p,
        uint[2][2] memory b,
        uint[2] memory b_p,
        uint[2] memory c,
        uint[2] memory c_p,
        uint[2] memory h,
        uint[2] memory k,
        uint[] memory input
    ) public payable {
        // Reminder: Remember that the primary inputs are ordered as follows:
        // We make sure to have the primary inputs ordered as follow:
        // [Root, NullifierS, CommitmentS, value_pub_in, value_pub_out]
        // ie, below is the index mapping of the primary input elements on the protoboard:
        // - Index of the "Root" field elements: {0}
        // - Index of the "NullifierS" field elements: [1, NumInputs + 1[
        // - Index of the "CommitmentS" field elements: [NumInputs + 1, NumOutputs + NumInputs + 1[
        // - Index of the "v_pub_in" field element: {NumOutputs + NumInputs + 1}
        // - Index of the "v_pub_out" field element: {NumOutputs + NumInputs + 1 + 1}
        //
        // 1. We re-assemble the full root digest from the 2 field elements it was packed into
        uint256[] memory digest_inputs = new uint[](2);
        digest_inputs[0] = input[0];
        digest_inputs[1] = input[1];
        require(
            roots[Bytes.sha256_digest_from_field_elements(digest_inputs)],
            "Invalid root: This root doesn't exist"
        );

        // 2. We re-assemble the nullifiers (JSInputs)
        //uint startIndexNullifier = 2;
        //uint stopIndexNullifier = startIndexNullifier + 2 * (jsIn);
        for(uint i = 2; i < 2 * (1 + jsIn); i += 2) {
            digest_inputs[0] = input[i];
            digest_inputs[1] = input[i+1];
            bytes32 current_nullifier = Bytes.sha256_digest_from_field_elements(digest_inputs);
            require(
                !nullifiers[current_nullifier],
                "Invalid nullifier: This nullifier has already been used"
            );
            nullifiers[current_nullifier] = true;
        }

        // 3. Verify the proof
        require(
            zksnark_verifier.verifyTx(a, a_p, b, b_p, c, c_p, h, k, input),
            "Invalid proof: Unable to verify the proof correctly"
        );

        // 4. We re-assemble the commitments (JSOutputs)
        //uint startIndexCommitment = stopIndexNullifier;
        //uint stopIndexCommitment = startIndexCommitment + 2 * (jsOut);
        for(uint i = 2 * (1 + (jsIn)); i < 2 * (1 + jsIn + jsOut); i += 2) {
            digest_inputs[0] = input[i]; // See the way the inputs are ordered in the extended proof
            digest_inputs[1] = input[i+1];
            bytes32 current_commitment = Bytes.sha256_digest_from_field_elements(digest_inputs);
            uint commitmentAddress = insert(current_commitment);
            emit LogAddress(commitmentAddress);
        }

        // 5. We get the vpub_in in wei
        //uint vpub_in_index = stopIndexCommitment;
        uint64 vpub_in = Bytes.get_value_from_inputs(Bytes.int256ToBytes8(input[2 * (1 + jsIn + jsOut)]));

        // If the vpub_in is > 0, we need to make sure the right amount is paid
        if (vpub_in > 0) {
            require(
                msg.value == vpub_in,
                "Wrong msg.value: Value paid is not correct"
            );
        } else {
            // If vpub_in is = 0, since we have a payable function, we need to
            // send the amount paid back to the caller
            msg.sender.transfer(msg.value);
        }

        // 6. Get vpub_out in wei
        //uint vpub_out_index = vpub_in_index + 1; // Should equal `nbInputs - 1`
        uint64 vpub_out = Bytes.get_value_from_inputs(Bytes.int256ToBytes8(input[2 * (1 + jsIn + jsOut) + 1]));

        // If value_pub_out > 0 then we do a withdraw
        // We retrieve the msg.sender and send him the appropriate value IF proof is valid
        if (vpub_out > 0) {
            msg.sender.transfer(vpub_out);
        }

        // Add the new root to the list of existing roots
        bytes32 currentRoot = getRoot();
        roots[currentRoot] = true;
        emit LogMerkleRoot(currentRoot);

        // Emit the all the coins' secret data encrypted with the recipients' respective keys
        emit LogSecretCiphers(ciphertext1);
        emit LogSecretCiphers(ciphertext2);
    }
}
