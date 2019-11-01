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

    uint constant size_value = 64;

    // Constants regarding the hash digest length, the prime number used and its associated length in bits and the max values (v_in and v_out)
    uint constant digest_length = 256;
    // uint r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // field_capacity = ceil ( log_2(r) ) - 1
    uint constant field_capacity = 253;
    uint packing_residue_length = digest_length > field_capacity ? digest_length % field_capacity : 0;

    // Number of residual bits from packing of 256-bit long string into 253-bit long field elements to which are added the public value of size 64 bits
    uint length_bit_residual = 2 * size_value + packing_residue_length * (1 + 2 * jsIn + jsOut);
    // Number of field elements needed to pack this number of bits
    uint nb_field_residual = (length_bit_residual + field_capacity - 1) / field_capacity;

    // The number of public inputs is:
    // - 1 (the root)
    // - jsIn (the nullifiers)
    // - jsOut (the commitments)
    // - 1 (hsig)
    // - JsIn (the message auth. tags)
    // - nb_field_residual (the residual bits not fitting in a single field element and the in and out public values)
    uint nbInputs = 1 + jsIn + jsOut + 1 + jsIn + nb_field_residual;

    // Contract variable that indicates the address of the token contract
    // If token = address(0) then the mixer works with ether
    address public token;

    // Event to emit the address of a commitment in the merke tree
    // Allows for faster execution of the "Receive" functions on the receiver side.
    // The ciphertext of a note is emitted along the address of insertion in the tree
    // Thus, instead of checking that the decrypted note is represented somewhere in the tree, the recipient just needs
    // to check that the decrypted note opens the commitment at the emitted address
    event LogAddress(uint commAddr);

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
    }

    // ============================================================================================ //
    // Reminder: The primary inputs are either field elements, hash digest or binary arrays.
    // As a field element may not represent an entire hash digest, we formatted the latter in two parts:
    // a field element and aggregated the remaining bits into (a) field element(s): the residual field element(s).
    // For efficiency we also added in these residual field elements the public values (bit arrays of 64 bits).
    //
    // Reminder: Remember that the primary inputs are ordered as follows:
    // We make sure to have the primary inputs ordered as follow:
    // [Root, NullifierS, CommitmentS, h_sig, h_iS, Residual Field Element(S)]
    // ie, below is the index mapping of the primary input elements on the protoboard:
    // - Index of the "Root" field elements: {0}
    // - Index of the "NullifierS" field elements: [1, NumInputs + 1[
    // - Index of the "CommitmentS" field elements: [NumInputs + 1, NumOutputs + NumInputs + 1[
    // - Index of the "h_sig" field element: {NumOutputs + NumInputs + 1}
    // - Index of the "Message Authentication TagS" (h_i) field elements: [NumOutputs + NumInputs + 1 + 1, NumOutputs + NumInputs + 1 + NumOuputs [
    // - Index of the "Residual Field Element(s)" field elements: [NumOutputs + NumInputs + 1 + NumOuputs + 1 , NumOutputs + NumInputs + 1 + NumOuputs + 1 + nb_field_residual]
    //
    // The Residual field elements are structured as follows:
    // - v_pub_in [0, size_value[
    // - v_pub_out [size_value + 1, 2*size_value[
    // - h_sig remaining bits [2*size_value + 1, 2*size_value + (digest_length-field_capacity)[
    // - nullifierS remaining bits [2*size_value + (digest_length-field_capacity) + 1, 2*size_value + (1+NumInputs)*(digest_length-field_capacity)[
    // - commitmentS remaining bits [2*size_value + (1+NumInputs)*(digest_length-field_capacity) + 1, 2*size_value + (1+NumInputs+NumOutputs)*(digest_length-field_capacity)[
    // - message authentication tagS remaining bits [2*size_value + (1+NumInputs+NumOutputs)*(digest_length-field_capacity) + 1, 2*size_value + (1+2*NumInputs+NumOutputs)*(digest_length-field_capacity)]
    // ============================================================================================ //

    // This function is used to extract the remaining bits of the nullifierS and commitmentS from the residual field element(S)
    //
    // We first compute the offset (to forego the v_pubs and h_sig remaining bits)
    // (v_pub_in || v_pub_out || h_sig_packing_residual_bits || nullifierS_packing_residual_bits || commitmentS_packing_residual_bits || hiS_packing_residual_bits)
    //   64 bits      64 bits             3 bits                            3 bits                                3 bits                           3 bits
    //                                                        ^
    //                                                        |
    //                                                      offset
    //                                                        ^                ^
    //                                                        | >            < | >
    //                                                      start             end
    // The position `start` points to the index of the first bit to extract, and `length` specifies the number of bits to extract.
    // Thus, the position `end` points to the index `start + length - 1` which is the index of the last bit to extract.
    function extract_extra_bits(uint start, uint length, uint[] memory primary_inputs) public view returns (bytes1) {
        // The residual bits from the packing of a digest may be written over (at most) two field elements
        // as such, we will (at most) manipulate 2 bytes during the extraction
        require(
            length < 16,
            "More than 2 bytes extracted"
        );

        // If we do not want to extract any bits, return 0
        if (length == 0) {
            return bytes1(0x0);
        }

        // We first compute the offset (to forego the v_pubs and h_sig remaining bits)
        uint offset = 2 * size_value + packing_residue_length;

        // We then compute the position of the last bit to retrieve
        uint end = start + length - 1;

        // The residual bits from the packing of a digest may be written over (at most) two field elements
        // (if residual_bits_length > field_capacity) as such we compute the indices of the
        // first and last field elements they are located at
        //
        // Here we retrieve the indices of the primary inputs containing the bits we want to extract
        uint first_residual_field_element_index = 1 + 1 + 2 * jsIn + jsOut + (offset + start)/field_capacity;
        uint second_residual_field_element_index = first_residual_field_element_index;
        if (nb_field_residual > 1) {
            // Multiple field elements were needed to represent all the residual bits
            // hence we may need to extract bits written in 2 field elements
            second_residual_field_element_index = 1 + 1 + 2 * jsIn + jsOut + (offset + start + length-1)/field_capacity;
        }

        // Since every Ethereum word is encoded on 256-bits, and since each primary input
        // is a field element which may be encoded on a different number of bits (253 bits
        // in the context of the bn256 curve for eg.), every field element may be front-padded
        // by 0's when represented as Ethereum words.
        // Following the example of the bn256 scalar field element, we would have:
        //                      Ethereum word = [000 10101....1]
        //                                       ^^^  ^^^^^^^^^
        //                                        |       |
        //                                     padding   Field element encoding
        //
        // Here, we compute the padding length in the field elements containing the remaining bits
        // The padding is either `packing_residue_length` (if we fill a whole field element)
        // or `digest_length - len(v_in || v_out || hsig || {sn} || {cm} || {h})`
        uint padding_start = packing_residue_length;
        uint padding_end = padding_start;
        // We check if `second_residual_field_element_index` points to the last byte.
        // The last byte may not be full, and thus have more padding.
        if (primary_inputs.length - 1 == second_residual_field_element_index) {
            padding_end = digest_length - ((offset + packing_residue_length*(2*jsIn + jsOut)) % field_capacity);
        }
        // We check if the last byte is the same as the first byte, if so we update the padding.
        if (second_residual_field_element_index == first_residual_field_element_index) {
            padding_start = padding_end;
        }

        // We can now compute the bytes; indices of the remaining bits in both field elements
        // and retrieve them.
        // Remember that our field element is represented as an Ethereum word as:
        //                      Ethereum word = [000 v_in||v_out||h_sig||{nf}||{cm}||{h_i}]
        //                                       ^^^  ^^^^^^^^^^^^^^^^  ^  ^^^^^^^^^^^^^^^
        //                                        |                  ___|
        //                                     padding               |
        //                                                           |
        //                                                         offset
        //
        uint index_start_byte = (padding_start + offset + start)/8;
        bytes1 start_byte = bytes32(primary_inputs[first_residual_field_element_index])[index_start_byte];
        uint index_end_byte = (padding_end + offset + end)/8;
        bytes1 end_byte = bytes32(primary_inputs[second_residual_field_element_index])[index_end_byte];

        // We now can recombine the two bytes.
        // To do so, we consider the binary array `res_bin = [start_byte || end_byte]` as the bit encoding of a number `res`
        // Note that the we are in big-endian, as such the most significant bit of `res_bin` is the first bit.
        // By definition of binary encoding we have,
        // res = Sum_{i=0}^{16-1} res_bin[i] * 2**(16-1-i)
        // ------- let's split the sum in two to make start_byte and end_byte appear
        //     = Sum_{i=0}^{8-1} res_bin[i] * 2**(16-1-i) + Sum_{i=8}^{16-1} res_bin[i] * 2**(16-1-i)
        // ------- now the first sum corresponds to encoding end_byte and the second start_byte
        //         we note that res_bin[i] = start_byte[i] for i < 8
        //         likewise, res_bin[i] = end_byte[i - 8] for 7 < i < 16
        //     = Sum_{i=0}^{8-1} start_byte[i] * 2**(16-1-i) + Sum_{i=8}^{16-1} end_byte[i-8] * 2**(16-1-i)
        // ------- we reorder the indices to have end_byte[i] (we have j = i - 8), and factorise by 2**8 in the left sum
        //     = 2**8 * Sum_{i=0}^{8-1} end_byte[i] * 2**(8-1-i) + Sum_{j=0}^{8-1} start_byte[j] * 2**(8-1-j)
        // ------- we can now see the relationship between the encoding of res_bin and the encodings of end_byte and start_byte
        //     = 2**8 * uint8(start_byte) + uint8(end_byte)
        uint16 res = (2**8) * uint8(start_byte) + uint8(end_byte);
        // The bit representation of res is now something like this (b_x representing the x^{th} bit):
        // b_0 || ... || b_{start-1} || b_{start} || ... || b_{end} || b_{end + 1} || ... || b_15
        //                              ^                         ^
        //                              |_________________________|
        //                                           |
        //                                  (length) asked bits
        // To get the needed bits, we need to discard the unneeded ones before and after.
        // First we compute the index of the first bit needed (bit_start) in start_byte.
        uint index_bit_start = (padding_start + offset + start) % 8;
        // We need to remove all the bits before this index.
        // As the most significant bit of the byte is the first, the binary operation
        // "res << index_bit_start" corresponds to multiplying by 2**index_bit_start.
        res = res * uint16(2**index_bit_start);
        // We now have something like this:
        // b_{start} || ... || b_{end} || b_{end + 1} || ... || b_15 || 0 || ... || 0
        // ^                         ^                                  ^           ^
        // |_________________________|                                  |___________|
        //              |                                                     |
        //     (length) asked bits                                          padding
        // We need to remove all the bits after b_end which is at location length-1, hence discard (16 - length) bits on the right.
        // Similarly, the binary operation "res >> 16-length" corresponds to dividing by 2**(16 - length)
        res = res / uint16(2**(16 - length));

        // We now have something like this:
        // 0 || ... || 0 || b_{start} || ... || b_{end}
        //                  ^                         ^
        //                  |_________________________|
        //                               |
        //                      (length) asked bits
        // All the asked bits are in the second byte, we thus return this one.
        return bytes2(res)[1];
    }

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
        for(uint i = 1; i < 1 + jsIn; i++) {
            digest_input = primary_inputs[i];
            index = packing_residue_length*(i-1);
            bits_input = extract_extra_bits(index, packing_residue_length, primary_inputs);
            bytes32 current_nullifier = Bytes.sha256_digest_from_field_elements(digest_input, bits_input);
            require(
                !nullifiers[current_nullifier],
                "Invalid nullifier: This nullifier has already been used"
            );
            nullifiers[current_nullifier] = true;
        }
    }

    function assemble_commitments_and_append_to_state(uint[] memory primary_inputs) internal {
        // We re-assemble the commitments (JSOutputs)
        uint index;
        bytes1 bits_input;
        for(uint i = 1 + jsIn ; i < 1 + jsIn + jsOut; i ++) {
            // See the way the inputs are ordered in the extended proof
            index = packing_residue_length*(i-1);
            bits_input = extract_extra_bits(index, packing_residue_length, primary_inputs);
            bytes32 current_commitment = Bytes.sha256_digest_from_field_elements(primary_inputs[i], bits_input);
            uint commitmentAddress = insert(current_commitment);
            emit LogAddress(commitmentAddress);
        }
    }

    function process_public_values(uint[] memory primary_inputs) internal {
        // 1. We get the vpub_in in wei
        // We know vpub_in corresponds to the first 64 bits of the first residual field element after padding.
        // We start by computing the padding .
        uint padding = packing_residue_length;
        // Update the padding if the public values and remainder bits fit in one field element
        if (2*size_value+padding*(1+2*jsIn+jsOut) < field_capacity) {
            padding = digest_length - (2*size_value + packing_residue_length*(1+2*jsIn+jsOut));
        }

        // We retrieve the public value in, remove any extra bits (due to the padding) and inverse the bit order
        bytes32 vpub_bytes = (bytes32(primary_inputs[1 + 1 + 2*jsIn + jsOut]) << padding) >> (digest_length-size_value);
        vpub_bytes = Bytes.swap_bit_order(vpub_bytes) >> (digest_length-size_value);
        uint64 vpub_in = Bytes.get_int64_from_bytes8(Bytes.int256ToBytes8(uint(vpub_bytes)));

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
        // We retrieve the public value out, remove any extra bits (due to the padding) and inverse the bit order
        vpub_bytes = (bytes32(primary_inputs[1 + 1 + 2*jsIn + jsOut]) << (padding+size_value)) >> (digest_length-size_value);
        vpub_bytes = Bytes.swap_bit_order(vpub_bytes) >> (digest_length-size_value);
        uint64 vpub_out = Bytes.get_int64_from_bytes8(Bytes.int256ToBytes8(uint(vpub_bytes)));

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
