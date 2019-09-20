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

    uint r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint log_r = 253;

    // The roots of the different updated trees
    mapping(bytes32 => bool) roots;

    // The public list of nullifiers (prevents double spend)
    mapping(bytes32 => bool) nullifiers;

    // JoinSplit description, gives the number of inputs (nullifiers) and outputs (commitments/ciphertexts) to receive and process
    // IMPORTANT NOTE: We need to employ the same JS configuration than the one used in the cpp prover
    // Here we use 2 inputs and 2 outputs (it is a 2-2 JS)
    // The number or public inputs is: 1 (the root) + 2 for each digest (nullifiers, commitments) + (1 + 1) (in and out public values) field elements
    uint constant jsIn = 2; // Nb of nullifiers
    uint constant jsOut = 2; // Nb of commitments/ciphertexts

    // We have 2 field elements for each digest (nullifierS (jsIn), commitmentS (jsOut), h_iS (jsIn) and h_sig)
    // The root, v_pub_in and v_pub_out are all represented by one field element, so we have 1 + 1 + 1 extra public values
    uint constant nbInputs = 1 + 2 * (jsIn + jsOut) + 1 + 1 + 2 * (1 + jsIn);

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
    // This event is key to obfuscate the transaction graph while enabling on-chain storage of the coins' data
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

    function extract_extra_bits(uint start, uint end, uint[] memory primary_inputs) public pure returns (bytes1) {
        require(
            end-start < 16,
            "invalid range"
        );
        uint16 res;
        uint offset = 2*64+3;
        uint index_start_bytes32 = (offset+start)/253;
        uint index_end_bytes32 = (offset+end)/253;
        uint padding = 3;
        if (primary_inputs.length-1 == index_end_bytes32) {
            padding = 256 - ( (offset + 3*(2*jsIn + jsOut)) % 253);
        }
        uint index_start_byte = (padding+offset+start)/8;
        uint8 start_byte = uint8(bytes32(primary_inputs[index_start_bytes32])[index_start_byte]);
        uint index_end_byte = (padding+offset+end)/8;
        uint8 end_byte = uint8(bytes32(primary_inputs[index_end_bytes32])[index_end_byte]);
        res = start_byte*(2**8)+end_byte;
        uint index_start_bit = (offset+padding+start)%8;
        res = res * uint16(2**index_start_bit);
        res = res / uint16(2**(16 - (end - start+1)));
        return bytes2(res)[1];
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

    // This function processes the primary inputs to append and check the root and nullifiers in the primary inputs (instance)
    // and modifies the state of the mixer contract accordingly
    // (ie: Appends the commitments to the tree, appends the nullifiers to the list and so on)
    function assemble_root_and_nullifiers_and_append_to_state(uint[] memory primary_inputs) internal {
        // 1. We check whether the root exists
        require(
            roots[bytes32(primary_inputs[0])],
            "Invalid root: This root doesn't exist"
        );

        // 2. We re-assemble the nullifiers (JSInputs)
        uint256 digest_input;
        bytes1 bits_input;
        uint index;
        for(uint i = 1; i < 1 + jsIn; i ++) {
            digest_input = primary_inputs[i];
            index = 3*(i-1);
            bits_input = extract_extra_bits(index, index+2, primary_inputs);
            bytes32 current_nullifier = Bytes.sha256_digest_from_field_elements(digest_input, bits_input);
            require(
                !nullifiers[current_nullifier],
                "Invalid nullifier: This nullifier has already been used"
            );
            nullifiers[current_nullifier] = true;
        }
    }


    function assemble_primary_inputs_and_hash(uint[] memory primary_inputs) public returns (bytes32) {
        bytes32[1 + jsIn + jsOut + 1 + 1 + 1 + jsIn] memory formatted_inputs;
        uint256 digest_input;
        bytes1 bits_input;
        uint index;
        uint padding = 0;
        if (3*(2*jsIn+jsOut) < (253-131)) {
            padding = 253 - (131 + 3*(2*jsIn+jsOut));
        }

        //Format and append the root
        bytes32 formatted = bytes32(primary_inputs[0]);
        require(
            uint256(formatted) < r,
            "invalid root: The root is not within range"
        );
        formatted_inputs[0] = formatted;

        //Format and append the nullifiers
        for(uint i = 1; i < 1 + jsIn; i ++) {
            digest_input = primary_inputs[i];
            index = 3*(i-1);
            bits_input = extract_extra_bits(index, index+2, primary_inputs);
            formatted = Bytes.sha256_digest_from_field_elements(digest_input, bits_input);
            require(
                uint256(formatted) < r,
                "invalid nullifier: This nullifier is not within range"
            );
            formatted_inputs[(i-1)/2 + 1] = formatted;
        }

        //Format and append the commitments
        for(uint i = 1 + jsIn; i < 1 + jsIn + jsOut; i ++) {
            digest_input = primary_inputs[i];
            index = 3*(i-1);
            bits_input = extract_extra_bits(index, index+2, primary_inputs);
            formatted = Bytes.sha256_digest_from_field_elements(digest_input, bits_input);
            require(
                uint256(formatted) < r,
                "invalid commitment: This commitment is not within range"
            );
            formatted_inputs[(i-1)/2 + 1] = formatted;
        }

        //Format and append the v_pub_in
        formatted = bytes32(primary_inputs[1 + 2*jsIn + jsOut]) >> (224-padding);
        require(
            uint256(formatted) < 18446744073709551615,
            "invalid value in: v_pub_in is not within range"
        );
        formatted_inputs[1 + jsIn + jsOut] = formatted;

        //Format and append the v_pub_out
        formatted = (bytes32(primary_inputs[1 + 2*jsIn + jsOut]) << (padding+32)) >> 224;
        require(
            uint256(formatted) < 18446744073709551615,
            "invalid value out: v_pub_out is not within range"
        );
        formatted_inputs[1 + jsIn + jsOut + 1] = formatted;

        //Format and append h_sig
        digest_input = primary_inputs[1 + jsIn + jsOut];
        bits_input = byte((bytes32(primary_inputs[1 + 2*jsIn + jsOut]) << (padding+15*8)) >> 5);
        formatted = Bytes.sha256_digest_from_field_elements(digest_input, bits_input);
        formatted_inputs[1 + jsIn + jsOut + 1 + 1] = formatted;

        //Format and append the h_iS
        for(uint i = 1 + jsIn + jsOut + 1; i < 1 + jsIn + jsOut + 1 + jsIn; i ++) {
            digest_input = primary_inputs[i];
            index = 3*(i-1);
            bits_input = extract_extra_bits(index, index+2, primary_inputs);
            formatted = Bytes.sha256_digest_from_field_elements(digest_input, bits_input);
            formatted_inputs[(i-1)/2 + 2] = formatted;
        }

        bytes32 hash_inputs = sha256(abi.encodePacked(formatted_inputs));

        return hash_inputs;
    }


    function assemble_commitments_and_append_to_state(uint[] memory primary_inputs) internal {
        // We re-assemble the commitments (JSOutputs)
        uint256 digest_input;
        uint index;
        bytes1 bits_input;
        for(uint i = 1 + jsIn ; i < 1 + jsIn + jsOut; i ++) {
            digest_input = primary_inputs[i]; // See the way the inputs are ordered in the extended proof
            index = 3*(i-1);
            bits_input = extract_extra_bits(index, index+2, primary_inputs);
            bytes32 current_commitment = Bytes.sha256_digest_from_field_elements(digest_input, bits_input);
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

    function emit_ciphertexts(string memory ciphertext0, string memory ciphertext1) internal {
        emit LogSecretCiphers(ciphertext0);
        emit LogSecretCiphers(ciphertext1);
    }
}
