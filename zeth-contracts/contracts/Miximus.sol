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

    // Smart contract responsible of on-chain verification of proofs
    Verifier public zksnark_verifier;

    // Denomination of the mixer
    uint denomination;

    // Constructor
    constructor(address _zksnark_verify, uint denom, uint depth) MerkleTreeSha256(depth) public {
        zksnark_verifier = Verifier(_zksnark_verify);
        denomination = denom;
    }

    // /!\ WARNING: Function used for a **development purpose** --> change the verifier contract
    function setVerifier (address _zksnark_verify) public {
        zksnark_verifier = Verifier(_zksnark_verify);
    }

    // Event to emit the address of a commitment in the merke tree
    event LogAddress(uint commAddr);

    // Event to emit the merkle root of a tree
    event LogMerkleRoot(bytes32 root);

    // Event to emit the ciphertexts of the coins' data to be sent to the recipient of the payment
    // This event is key to obfuscate the tranaction graph while enabling on-chain storage of the coins' data
    // (useful to ease backup of user's wallets)
    event LogSecretCiphers(bytes ciphertext);

    // Deposit takes a commitment as a parameter. The commitment in inserted in the Merkle Tree of commitment
    // in exchange of an amount of ether (the mixer's denomination) being paid
    function deposit(bytes32 commitment) public payable {
        // We assume that the denomination is an int multiple of ethers (to adjust if necessary)
        require(
            msg.value == (denomination * (1 ether)),
            "Wrong msg.value: Should equal the denomination of the mixer"
        );

        uint commitmentAddress = insert(commitment);
        emit LogAddress(commitmentAddress);

        // We need to padZero the tree root because when we generate the proof
        // The last byte get stripped
        //
        // Fix the issue with padZero: See if we can safely delete it and use the 2 inputs representing the root instead
        bytes32 currentRoot = getRoot();
        emit LogMerkleRoot(currentRoot);

        roots[currentRoot] = true;
    }

    // The withdraw function enables a user to redeem the mixer's denomination amount of ether by providing
    // a valid proof that he knows the pre-image of a commitment in the merkle tree that has never been "spent"
    function withdraw (
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
        // The recipient is part of the nullifier --> To change!
        address recipient = nullifierToAddress(flip_endianness(bytes32(input[2])));
        // See: https://solidity.readthedocs.io/en/v0.5.0/types.html#address
        // for more information on address payable type and conversion from and to address type
        address payable recipientAddr = address(uint160(recipient));

        // We re-assemble the full root digest from both field elements (created when we packed the
        // 256-bit digest into field elements, that are both encoded on 253 bits --> size of the field we use)
        uint256[] memory root_inputs = new uint[](2);
        root_inputs[0] = input[0]; // See the way the inputs are ordered in the extended proof
        root_inputs[1] = input[1];
        require(
            roots[Bytes.sha256_digest_from_field_elements(root_inputs)],
            "Invalid root: This root doesn't exist"
        );

        require(
            !nullifiers[padZero(flip_endianness(bytes32(input[2])))],
            "Invalid nullifier: This nullifier has already been used"
        );

        require(
            zksnark_verifier.verifyTx(a, a_p, b, b_p, c, c_p, h, k, input),
            "Invalid proof: Unable to verify the proof correctly"
        );

        // Send the right denomination to the recipient
        recipientAddr.transfer(denomination * (1 ether));

        // Declare the nullifier as being used (not usable anymore: prevents double spend)
        nullifiers[padZero(flip_endianness(bytes32(input[2])))] = true;
    }

    // The forward function enables a user who has been the recipient of a "private payment" in the past
    // (someone possessing the secret associated with a non-spent nullifier, and a commitment in the tree)
    // to use it to pay someone else (ie: "spend" his nullifier and creating a new commitment in the tree to pay someone else)
    //
    // This function basically does a payment via the use of commitments and zero knowledge proof verification on-chain
    function forward (
        bytes memory ciphertext,
        bytes32 commitment,
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
        address recipient  = nullifierToAddress(flip_endianness(bytes32(input[2])));

        require(
            msg.sender == recipient,
            "Invalid sender: The sender should be the address specified in the nullifier"
        );

        // We re-assemble the full root digest from both field elements (created when we packed the
        // 256-bit digest into field elements, that are both encoded on 253 bits --> size of the field we use)
        uint256[] memory root_inputs = new uint[](2);
        root_inputs[0] = input[0]; // See the way the inputs are ordered in the extended proof
        root_inputs[1] = input[1];
        require(
            roots[Bytes.sha256_digest_from_field_elements(root_inputs)],
            "Invalid root: This root doesn't exist"
        );

        require(
            !nullifiers[padZero(flip_endianness(bytes32(input[2])))],
            "Invalid nullifier: This nullifier has already been used"
        );
        require(
            zksnark_verifier.verifyTx(a, a_p, b, b_p, c, c_p, h, k, input),
            "Invalid proof: Unable to verify the proof correctly"
        );

        // We insert the new commitment in the tree once:
        // 1. We checked that the forward request was triggered by the recipient of a past payment who has an "unspent nullifier"
        // 2. The proof given is valid
        uint commitmentAddress = insert(commitment);
        emit LogAddress(commitmentAddress);

        // Emit the coin's secret data encrypted with the recipient's key
        emit LogSecretCiphers(ciphertext);

        bytes32 currentRoot = getRoot();
        emit LogMerkleRoot(currentRoot);
        roots[currentRoot] = true;
    }

    function nullifierToAddress(bytes32 source) internal pure returns(address) {
        bytes20[2] memory y = [bytes20(0), 0];
        assembly {
            // mstore(p, v) signifies --> mem[p..(p+32)) := v
            // where, mem[a...b) signifies the bytes of memory starting
            // at position a up to (excluding) position b
            // Thus, here: mstore(y, source) means that we set the first 32bytes
            // of y (which is 40 bytes in total), to the value stored in source
            // The remaining 8bytes of the last element of y (y[1]) remain 0
            mstore(y, source)
            mstore(add(y, 20), source)
        }
        return(address(y[0]));
    }

    // Hack to side step the fact that libsnark only allows 253 bit chunks in its output
    // to overcome this we only validate the first 252 bits of the merkle root
    // and the nullifier. We set the last byte to zero.
    function padZero(bytes32 x) internal pure returns(bytes32) {
        return(x & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0);
    }

    // Functions used to flip endianness
    // Example:
    // Input: 1011...01100
    // Output: 00110...1101
    function flip_endianness(bytes32 a) internal pure returns(bytes32) {
        uint r;
        uint i;
        uint b;
        for (i=0; i<32; i++) {
            b = (uint(a) >> ((31-i)*8)) & 0xff;
            b = reverseByte(b);
            r += b << (i*8);
        }
        return bytes32(r);
    }

    // Example:
    // Input: 8 (decimal) -> 0000 1000 (binary)
    // Output: 0001 0000 (binary) -> 16 (decimal)
    function reverseByte(uint a) internal pure returns (uint) {
        uint c = 0xf070b030d0509010e060a020c0408000;

        return (( c >> ((a & 0xF)*8)) & 0xF0)   +
               (( c >> (((a >> 4)&0xF)*8) + 4) & 0xF);
    }
}
