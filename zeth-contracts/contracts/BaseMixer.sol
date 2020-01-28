// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

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
    // Here we use 2 inputs and 2 outputs (it is a 2-2 JS)
    uint constant jsIn = 2; // Nb of nullifiers
    uint constant jsOut = 2; // Nb of commitments/ciphertexts

    // Size of the public values in bits
    uint constant public_value_length = 64;

    // Constants regarding the hash digest length, the prime number used and its associated length in bits and the max values (v_in and v_out)
    // uint r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // field_capacity = floor( log_2(r) )
    uint constant digest_length = 256;
    uint constant field_capacity = 253;

    // Variable representing the number of "residual" bits we can expect from converting a hash digest into a field element
    // see primary input `residual_bits` in Reminder below
    uint constant packing_residue_length = digest_length - field_capacity;

    // Number of hash digests in the primary inputs
    uint constant nb_hash_digests = 1 + 2*jsIn + jsOut;

    // Total number of residual bits from packing of 256-bit long string into 253-bit long field elements
    // to which are added the public value of size 64 bits
    uint constant length_bit_residual = 2 * public_value_length + packing_residue_length * nb_hash_digests;
    // uint nb_field_residual = (length_bit_residual + field_capacity - 1) / field_capacity;

    // Padding size in the residual field element (we require a single residual f.e. (c.f. constructor))
    uint constant padding_size = digest_length - length_bit_residual;

    // The number of public inputs is:
    // - 1 (the root)
    // - jsIn (the nullifiers)
    // - jsOut (the commitments)
    // - 1 (hsig)
    // - JsIn (the message auth. tags)
    // - nb_field_residual (the residual bits not fitting in a single field element and the in and out public values)
    // uint constant nbInputs = 1 + nb_hash_digests + nb_field_residual;

    // Contract variable that indicates the address of the token contract
    // If token = address(0) then the mixer works with ether
    address public token;

    // The unit used for public values (ether in and out), in Wei. Must match
    // the python wrappers. Use Szabos (10^12 Wei).
    uint64 constant public_unit_value_wei = 1 szabo;

    // Event to emit the address of a commitment in the merke tree
    // Allows for faster execution of the "Receive" functions on the receiver side.
    // The ciphertext of a note is emitted along the address of insertion in the tree
    // Thus, instead of checking that the decrypted note is represented somewhere in the tree, the recipient just needs
    // to check that the decrypted note opens the commitment at the emitted address
    event LogCommitment(uint commAddr, bytes32 commit);

    // Event to emit the root of a the merkle tree
    event LogMerkleRoot(bytes32 root);

    // Event to emit the encryption public key of the sender and ciphertexts of the coins' data to be sent to the recipient of the payment
    // This event is key to obfuscate the transaction graph while enabling on-chain storage of the coins' data
    // (useful to ease backup of user's wallets)
    event LogSecretCiphers(bytes32 pk_sender, bytes ciphertext);

    // Debug only
    event LogDebug(string message);

    // Constructor
    constructor(uint depth, address token_address, address hasher_address) MerkleTreeMiMC7(hasher_address, depth) public {
        // We log the first root to get started
        bytes32 initialRoot = getRoot();
        roots[initialRoot] = true;
        emit LogMerkleRoot(initialRoot);

        token = token_address;

        // We require the need of a single residual field elements
        require(
            field_capacity < digest_length,
            "A hash digest fits in a single field element."
        );
        require(
            length_bit_residual < field_capacity,
            "Too many input and output notes considered."
        );
    }

    // ============================================================================================ //
    // Reminder: Remember that the primary inputs are ordered as follows:
    // We make sure to have the primary inputs ordered as follow:
    // [Root, NullifierS, CommitmentS, h_sig, h_iS, Residual Field Element(S)]
    // ie, below is the index mapping of the primary input elements on the protoboard:
    // - Index of the "Root" field elements: {0}
    // - Index of the "NullifierS" field elements: [1, 1 + NumInputs[
    // - Index of the "CommitmentS" field elements: [1 + NumInputs, 1 + NumInputs + NumOutputs[
    // - Index of the "h_sig" field element: {1 + NumInputs + NumOutputs}
    // - Index of the "Message Authentication TagS" (h_i) field elements: [1 + NumInputs + NumOutputs + 1, 1 + NumInputs + NumOuputs + 1 + NumInputs[
    // - Index of the "Residual Field Element(s)" field elements: [1 + NumInputs + NumOutputs + 1 + NumInputs, 1 + NumInputs + NumOuputs + 1 + NumInputs + nb_field_residual[
    //
    // The Residual field elements are structured as follows:
    // - v_pub_in [0, public_value_length[
    // - v_pub_out [public_value_length, 2*public_value_length[
    // - h_sig remaining bits [2*public_value_length, 2*public_value_length + (digest_length-field_capacity)[
    // - nullifierS remaining bits [2*public_value_length + (digest_length-field_capacity), 2*public_value_length + (1+NumInputs)*(digest_length-field_capacity)[
    // - commitmentS remaining bits [2*public_value_length + (1+NumInputs)*(digest_length-field_capacity), 2*public_value_length + (1+NumInputs+NumOutputs)*(digest_length-field_capacity)[
    // - message authentication tagS remaining bits [2*public_value_length + (1+NumInputs+NumOutputs)*(digest_length-field_capacity), 2*public_value_length + (1+2*NumInputs+NumOutputs)*(digest_length-field_capacity)]
    // ============================================================================================ //

    // This function is used to extract the public values (vpub_in and vpub_out) from the residual field element(S)
    function assemble_public_values(uint[] memory primary_inputs) public pure returns (uint64 vpub_in, uint64 vpub_out){
        // We know vpub_in corresponds to the first 64 bits of the first residual field element after padding.
        // We retrieve the public value in, remove any extra bits (due to the padding) and inverse the bit order
        uint residual_hash_size = packing_residue_length*nb_hash_digests;

        bytes32 vpub_bytes = bytes32(primary_inputs[1 + nb_hash_digests]) >> (residual_hash_size + public_value_length);
        vpub_in = uint64(Bytes.get_last_8_bytes(uint(vpub_bytes)));

        // We retrieve the public value out, remove any extra bits (due to the padding) and inverse the bit order
        vpub_bytes = bytes32(primary_inputs[1 + nb_hash_digests]) >> residual_hash_size;
        vpub_out = uint64(Bytes.get_last_8_bytes(uint(vpub_bytes)));
    }

    // This function is used to reassemble hsig given the the primary_inputs
    // To do so, we extract the remaining bits of hsig from the residual field element(S) and combine them with the hsig field element
    function assemble_hsig(uint[] memory primary_inputs) public pure returns (bytes32 hsig){

        // We know hsig residual bits correspond to the 128th to 130st bits of the first residual field element after padding.
        // We retrieve hsig's residual bits and remove any extra bits (due to the padding)
        bytes32 hsig_bytes = (bytes32(primary_inputs[1 + nb_hash_digests]) << padding_size + 2*public_value_length) >> field_capacity;
        bytes1 bits_input = Bytes.get_last_byte(hsig_bytes);

        // We reassemble the residual bits with the field element
        hsig = Bytes.sha256_digest_from_field_elements(primary_inputs[1 + jsIn + jsOut] << (digest_length - field_capacity), bits_input);
    }

    // This function is used to reassemble the nullifiers given the nullifier index [0, jsIn[ and the primary_inputs
    // To do so, we extract the remaining bits of the nullifier from the residual field element(S) and combine them with the nullifier field element
    function assemble_nullifier(uint index, uint[] memory primary_inputs) public pure returns (bytes32 nf){
        // We first check that the nullifier we want to retrieve exists
        require(
            index < jsIn,
            "nullifier index overflow"
        );
        // We offset the nullifier index by the number of values preceding the nullifiers in the primary inputs:
        // the root (1)
        uint nullifier_index = 1 + index;

        // We compute the nullifier's residual bits index and check the 1st f.e. indeed comprises it
        // See the way the residual bits are ordered in the extended proof
        uint nf_bit_index = 2*public_value_length + nullifier_index * packing_residue_length;
        require(
            field_capacity >= nf_bit_index + packing_residue_length,
            "nullifier written in different residual bit f.e."
        );

        // We retrieve nf's residual bits and remove any extra bits (due to the padding)
        bytes32 nf_bytes = (bytes32(primary_inputs[1 + nb_hash_digests]) << padding_size + nf_bit_index) >> field_capacity;
        bytes1 bits_input = Bytes.get_last_byte(nf_bytes);
        // We reassemble the residual bits with the field element
        nf = Bytes.sha256_digest_from_field_elements(primary_inputs[nullifier_index] << (digest_length - field_capacity), bits_input);
    }

    // This function is used to reassemble the commitment given the commitment index [0, jsOut[ and the primary_inputs
    // To do so, we extract the remaining bits of the commitment from the residual field element(S) and combine them with the commitment field element
    function assemble_commitment(uint index, uint[] memory primary_inputs) public pure returns (bytes32 cm){
        // We first check that the commitment we want to retrieve exists
        require(
            index < jsOut,
            "commitment index overflow"
        );
        // We offset the commitment index by the number of values preceding the commitments in the primary inputs:
        // the root (1) and the nullifiers (jsIn)
        uint commitment_index = 1 + jsIn + index;

        // We compute the commitment's residual bits index and check the 1st f.e. indeed comprises it
        // See the way the residual bits are ordered in the extended proof
        uint commitment_bit_index = 2*public_value_length + commitment_index * packing_residue_length;
        require(
            field_capacity >= commitment_bit_index + packing_residue_length,
            "commitment written in different residual bit f.e."
        );

        // We retrieve cm's residual bits and remove any extra bits (due to the padding)
        bytes32 cm_bytes = (bytes32(primary_inputs[1 + nb_hash_digests]) << padding_size + commitment_bit_index) >> field_capacity;
        bytes1 bits_input = Bytes.get_last_byte(cm_bytes);

        // We reassemble the residual bits with the field element
        cm = Bytes.sha256_digest_from_field_elements(primary_inputs[commitment_index] << (digest_length - field_capacity), bits_input);
    }

    // This function processes the primary inputs to append and check the root and nullifiers in the primary inputs (instance)
    // and modifies the state of the mixer contract accordingly
    // (ie: Appends the commitments to the tree, appends the nullifiers to the list and so on)
    function check_mkroot_nullifiers_hsig_append_nullifiers_state(
        uint[2][2] memory vk,
        uint[] memory primary_inputs) internal {
        // 1. We re-assemble the full root digest and check it is in the tree
        require(
            roots[bytes32(primary_inputs[0])],
            "Invalid root: This root doesn't exist"
        );

        // 2. We re-assemble the nullifiers (JSInputs) and check they were not already seen
        bytes32[jsIn] memory nfs;
        for(uint i; i < jsIn; i++) {
            nfs[i] = assemble_nullifier(i, primary_inputs);
            require(
                !nullifiers[nfs[i]],
                "Invalid nullifier: This nullifier has already been used"
            );
            nullifiers[nfs[i]] = true;
        }

        // 3. We re-compute h_sig, re-assemble the expected h_sig and check they are equal
        // (i.e. that h_sig re-assembled was correctly generated from vk)
        bytes32 expected_hsig = sha256(abi.encodePacked(nfs, vk));
        bytes32 hsig = assemble_hsig(primary_inputs);
        require(
            expected_hsig == hsig,
            "Invalid hsig: This hsig does not correspond to the hash of vk and the nfs"
        );
    }


    function assemble_commitments_and_append_to_state(uint[] memory primary_inputs) internal {
        // We re-assemble the commitments (JSOutputs)
        for(uint i; i < jsOut; i++) {
            bytes32 current_commitment = assemble_commitment(i, primary_inputs);
            uint commitmentAddress = insert(current_commitment);
            emit LogCommitment(commitmentAddress, current_commitment);
        }
    }

    function process_public_values(uint[] memory primary_inputs) internal {
        // 0. We get vpub_in and vpub_out
        uint vpub_in_zeth_units;
        uint vpub_out_zeth_units;
        (vpub_in_zeth_units, vpub_out_zeth_units) = assemble_public_values(primary_inputs);

        // 1. We get the vpub_in in wei
        uint vpub_in = vpub_in_zeth_units * public_unit_value_wei;

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
        uint vpub_out = vpub_out_zeth_units * public_unit_value_wei;

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

    function emit_ciphertexts(bytes32 pk_sender, bytes memory ciphertext0, bytes memory ciphertext1) internal {
        emit LogSecretCiphers(pk_sender, ciphertext0);
        emit LogSecretCiphers(pk_sender, ciphertext1);
    }
}
