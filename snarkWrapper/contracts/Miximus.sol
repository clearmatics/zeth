pragma solidity ^0.4.22;

import "MerkleTree.sol";
import "Verifier.sol";

contract Miximus is MerkleTree {
    mapping(bytes32 => bool) roots;
    mapping(bytes32 => bool) nullifiers;
    Verifier public zksnark_verify;

    event Withdraw(address); 

    // Constructor
    // TODO: Add the denomination to the mixer constructor to customize the denomination of the mixer as we deploy it
    function Miximus (address _zksnark_verify) {
        zksnark_verify = Verifier(_zksnark_verify);
    }
    
    // Function used for a development purpose to change the contract verifying the proof
    function setVerifier (address _zksnark_verify) {
        zksnark_verify = Verifier(_zksnark_verify);
    }

    // Deposit takes a commitment as a parameter
    // The commitment in inserted in the Merkle Tree of commitment
    function deposit (bytes32 leaf) payable {
        // Make sure the user paid the good denomination to append a commitment in the tree
        // (Need to pay 1ether to participate in the mixing)
        require(msg.value == 1 ether);
        insert(leaf);
        // We need to padZero the tree root because when we generate the proof
        // The last byte get stripped
        roots[padZero(getTree()[1])] = true;
    }

    // The withdraw function enables a user to redeem 1 ether by providing 
    // a valid proof of knowledge of the secret
    function withdraw (
        uint[2] a,
        uint[2] a_p,
        uint[2][2] b,
        uint[2] b_p,
        uint[2] c,
        uint[2] c_p,
        uint[2] h,
        uint[2] k,
        uint[] input
    ) returns (address) {
        address recipient  = nullifierToAddress(reverse(bytes32(input[2])));
        // If we didn't padZero the root in the deposit function
        // This require would fail all the time
        require(roots[reverse(bytes32(input[0]))], "[DEBUG REQUIRE] Invalid root");

        require(!nullifiers[padZero(reverse(bytes32(input[2])))], "[DEBUG REQUIRE] Invalid nullifier");
        require(zksnark_verify.verifyTx(a, a_p, b, b_p, c, c_p, h, k, input), "[DEBUG REQUIRE] Invalid proof");

        // TODO: Use the denomination set in the Mixer constructor rather than 1 ether
        recipient.transfer(1 ether);
        nullifiers[padZero(reverse(bytes32(input[2])))] = true;
        Withdraw(recipient);
        return(recipient);
    }
    
    // The forward function enables a user who has been the recipient
    // of a "private payment" in the past 
    // (thus possessing the secret associated with a non-spent nullifier, and a commitment in the tree)
    // to use it to pay someone else 
    // (ie: "spend" his nullifier and creating a new commitment in the tree to pay someone else)
    function forward (
        bytes32 leaf,
        uint[2] a,
        uint[2] a_p,
        uint[2][2] b,
        uint[2] b_p,
        uint[2] c,
        uint[2] c_p,
        uint[2] h,
        uint[2] k,
        uint[] input
    ) returns (address) {
        address recipient  = nullifierToAddress(reverse(bytes32(input[2])));
        require(msg.sender == recipient);

        require(roots[reverse(bytes32(input[0]))], "[DEBUG REQUIRE] Invalid root");
        require(!nullifiers[padZero(reverse(bytes32(input[2])))], "[DEBUG REQUIRE] Invalid nullifier");
        require(zksnark_verify.verifyTx(a, a_p, b, b_p, c, c_p, h, k, input), "[DEBUG REQUIRE] Invalid proof");

        // We insert the new commitment in the tree once:
        // 1. We checked that the forward request was triggered by the recipient of a past payment who has an "unspent nullifier"
        // 2. The proof given is valid
        insert(leaf);
        roots[padZero(getTree()[1])] = true;
        // The caller of the "forward" function now has "spent" his nullifier to pay someone else 
        // This allow for people to use the payments they receive as a way to pay others
        nullifiers[padZero(reverse(bytes32(input[2])))] = true;
        return(recipient);
    }

    function nullifierToAddress(bytes32 source) returns(address) {
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
    function padZero(bytes32 x) returns(bytes32) {
        return(x & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0);
    }

    // Functions used to flip endianness
    // Example:
    // Input: 1011...01100
    // Output: 00110...1101
    function reverse(bytes32 a) public pure returns(bytes32) {
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
    function reverseByte(uint a) public pure returns (uint) {
        uint c = 0xf070b030d0509010e060a020c0408000;

        return (( c >> ((a & 0xF)*8)) & 0xF0)   +  
               (( c >> (((a >> 4)&0xF)*8) + 4) & 0xF);
    }
}
