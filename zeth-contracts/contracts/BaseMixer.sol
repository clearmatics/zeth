pragma solidity ^0.5.0;

import "./MerkleTreeMiMC7.sol";
import "./Bytes.sol";

/*
 * Declare the ERC20 interface in order to handle ERC20 tokens transfers
 * to and from the Mixer. Note that we only declare the functions we are interested in,
 * namely, transferFrom() (used to do a Deposit), and transfer() (used to do a withdrawal)
**/
contract ERC20 {
    function transferFrom(address from, address to, uint256 value) public;
    function transfer(address to, uint256 value) public;
}

/*
 * ERC223 token compatible contract
**/
contract ERC223ReceivingContract {
    // See: https://github.com/Dexaran/ERC223-token-standard/blob/Recommended/Receiver_Interface.sol
    struct Token {
        address sender;
        uint value;
        bytes data;
        bytes4 sig;
    }

    function tokenFallback(address from, uint value, bytes memory data) public pure {
        Token memory tkn;
        tkn.sender = from;
        tkn.value = value;
        tkn.data = data;

         // see https://solidity.readthedocs.io/en/v0.5.5/types.html#conversions-between-elementary-types
        uint32 u = uint32(bytes4(data[0])) + uint32(bytes4(data[1]) >> 8) + uint32(bytes4(data[2]) >> 16) + uint32(bytes4(data[3]) >> 24);
        tkn.sig = bytes4(u);
    }
}

/*
 * BaseMixer implements the functions shared across all Mixers (regardless which zkSNARK is used)
**/
contract BaseMixer is MerkleTreeMiMC7, ERC223ReceivingContract {
    using Bytes for *;

    // The roots of the different updated trees
    mapping(bytes32 => bool) roots;

    // The public list of nullifiers (prevents double spend)
    mapping(bytes32 => bool) nullifiers;

    // JoinSplit description, gives the number of inputs (nullifiers) and outputs (commitments/ciphertexts) to receive and process
    // IMPORTANT NOTE: We need to employ the same JS configuration than the one used in the cpp prover
    // Here we use 2 inputs and 2 outputs (it is a 2-2 JS) TODO: how to make it dynamical throught config file
    uint constant jsIn = 2; // Nb of nullifiers
    uint constant jsOut = 2; // Nb of commitments/ciphertexts

    // We have 1 field elements for each digest (root, nullifiers, commitments) and 1 + 1 public value
    uint constant nbInputs = 1 + jsIn + jsOut + 1 + 1;

    // Contract variable that indicates the address of the token contract
    // If token = address(0) then the mixer works with ether
    address public token;

    // Contract variable that indicates the address of the hasher contract
    address public hasher;

    // Event to emit the address of a commitment in the merke tree
    // Allows for faster execution of the "Receive" functions on the receiver side.
    // The ciphertext of a note is emitted along the address of insertion in the tree
    // Thus, instead of checking that the decrypted note is represented somewhere in the tree, the recipient just needs
    // to check that the decrypted note opens the commitment at the emitted address
    event LogAddress(uint commAddr);

    // Event to emit the root of a the merkle tree
    event LogMerkleRoot(bytes32 root);

    // Event to emit the ciphertexts of the coins' data to be sent to the recipient of the payment
    // This event is key to obfuscate the tranaction graph while enabling on-chain storage of the coins' data
    // (useful to ease backup of user's wallets)
    event LogSecretCiphers(string ciphertext);

    // Debug only
    event LogDebug(string message);

    // Constructor
    constructor(uint depth, address token_address, address hasher_address) MerkleTreeMiMC7(hasher_address, depth) public {
        // We log the first root to get started
        bytes32 initialRoot = getRoot();
        roots[initialRoot] = true;
        emit LogMerkleRoot(initialRoot);

        token = token_address;
    }

    // ============================================================================================ //
    // Reminder: Remember that the primary inputs are ordered as follows:
    // We make sure to have the primary inputs ordered as follow:
    // [Root, NullifierS, CommitmentS, value_pub_in, value_pub_out]
    // ie, below is the index mapping of the primary input elements on the protoboard:
    // - Index of the "Root" field elements: {0}
    // - Index of the "NullifierS" field elements: [1, NumInputs + 1[
    // - Index of the "CommitmentS" field elements: [NumInputs + 1, NumOutputs + NumInputs + 1[
    // - Index of the "v_pub_in" field element: {NumOutputs + NumInputs + 1}
    // - Index of the "v_pub_out" field element: {NumOutputs + NumInputs + 1 + 1}
    // ============================================================================================ //

    // This function processes the primary inputs to append and check the root and nullifiers int he primary inputs (instance)
    // and modifies the state of the mixer contract accordingly
    // (ie: Appends the commitments to the tree, appends the nullifiers to the list and so on)
    function assemble_root_and_nullifiers_and_append_to_state(uint[] memory primary_inputs) internal {
        // 1. We re-assemble the full root digest from the 2 field elements it was packed into
        uint256[] memory digest_inputs = new uint[](2);
        digest_inputs[0] = primary_inputs[0];

        require(
            roots[bytes32(digest_inputs[0])],
            "Invalid root: This root doesn't exist"
        );

        // 2. We re-assemble the nullifiers (JSInputs)
        for(uint i = 1; i < 1 + 2*jsIn; i += 2) {
            digest_inputs[0] = primary_inputs[i];
            digest_inputs[1] = primary_inputs[i+1];
            bytes32 current_nullifier = Bytes.sha256_digest_from_field_elements(digest_inputs);
            require(
                !nullifiers[current_nullifier],
                "Invalid nullifier: This nullifier has already been used"
            );
            nullifiers[current_nullifier] = true;
        }
    }

    function assemble_commitments_and_append_to_state(uint[] memory primary_inputs) internal {
        // We re-assemble the commitments (JSOutputs)
        uint256[] memory digest_inputs = new uint[](2);
        for(uint i = 1 + 2 * jsIn ; i < 1 + 2*(jsIn + jsOut); i += 2) {
            digest_inputs[0] = primary_inputs[i]; // See the way the inputs are ordered in the extended proof
            digest_inputs[1] = primary_inputs[i+1];
            bytes32 current_commitment = Bytes.sha256_digest_from_field_elements(digest_inputs);
            uint commitmentAddress = insert(current_commitment);
            emit LogAddress(commitmentAddress);
        }
    }

    function process_public_values(uint[] memory primary_inputs) internal {
        // 1. We get the vpub_in in wei
        uint64 vpub_in = Bytes.get_value_from_inputs(Bytes.int256ToBytes8(primary_inputs[1 + 2*(jsIn + jsOut)]));

        // If the vpub_in is > 0, we need to make sure the right amount is paid
        if (vpub_in > 0) {
            if (token != address(0)) {
                ERC20 erc20Token = ERC20(token);
                erc20Token.transferFrom(msg.sender, address(this), vpub_in);
            } else {
                require(
                    msg.value == vpub_in,
                    "Wrong msg.value: Value paid is not correct"
                );
            }
        } else {
            // If vpub_in is = 0, since we have a payable function, we need to
            // send the amount paid back to the caller
            msg.sender.transfer(msg.value);
        }

        // 2. Get vpub_out in wei
        uint64 vpub_out = Bytes.get_value_from_inputs(Bytes.int256ToBytes8(primary_inputs[2*(1 + jsIn + jsOut)]));

        // If value_pub_out > 0 then we do a withdraw
        // We retrieve the msg.sender and send him the appropriate value IF proof is valid
        if (vpub_out > 0) {
            if (token != address(0)) {
                ERC20 erc20Token = ERC20(token);
                erc20Token.transfer(msg.sender, vpub_out);
            } else {
                msg.sender.transfer(vpub_out);
            }
        }
    }

    function add_and_emit_merkle_root(bytes32 root) internal {
        roots[root] = true;
        emit LogMerkleRoot(root);
    }

    function emit_ciphertexts(string memory ciphertext1, string memory ciphertext2) internal {
        emit LogSecretCiphers(ciphertext1);
        emit LogSecretCiphers(ciphertext2);
    }
}
