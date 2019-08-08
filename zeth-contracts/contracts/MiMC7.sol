pragma solidity ^0.5.0;

/*
 * Reference papers:
 *
 * \[AGRRT16]:
 * "MiMC: Efficient Encryption and Cryptographic Hashing with Minimal Multiplicative Complexity",
 * Martin Albrecht, Lorenzo Grassi, Christian Rechberger, Arnab Roy, and Tyge Tiessen,
 * ASIACRYPT 2016,
 * <https://eprint.iacr.org/2016/492.pdf>
 *
 * "One-way compression function"
 * Section: "Miyaguchi–Preneel"
 * <https://en.wikipedia.org/wiki/One-way_compression_function#Miyaguchi%E2%80%93Preneel>
**/

contract MiMC7 {
  function hash(bytes32 x, bytes32 y, bytes memory enc_seed) public pure returns (bytes32 out) {
    // See: https://github.com/ethereum/go-ethereum/blob/master/crypto/bn256/cloudflare/constants.go#L23
    uint r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    bytes32 seed = keccak256(enc_seed);
    bytes32 key = y; // y will be use used as round key of the block cipher as defined by Miyaguchi-Prenel construction

    assembly {
      // Load the "free memory pointer" to point to the next free memory address
      let roundConstant := mload(0x40)
      // 0x40 (free memory pointer) now becomes the next memory location
      mstore(0x40, add(roundConstant, 32))
      // We store the seed in the memory word/address pointed by roundConstant
      mstore(roundConstant, seed)

      // Round function f(message) = (message + key + roundConstant)^d
      // d (= exponent) = 7; #rounds = 91
      //
      // Note on the exponent: gcd(7, r - 1) = 1 which confirms that the monomial x^7 is a permutation in Fr
      // See: Proposition 1, Section 4 and section 5; https://eprint.iacr.org/2016/492.pdf
      //
      // In the first round the constant is not used
      let outPermutation := x

      // a = outPermutation + roundConstant + key mod r
      let a :=  addmod(outPermutation, key, r)
      // a2 = a^2 mod r
      let a2 := mulmod(a, a, r)
      // outPermutation = a^7 mod r (x^7 is the permutation polynomial used)
      outPermutation :=  mulmod(mulmod(mulmod(a2, a2, r), a2, r), a, r)

      for {let j := 0} slt(j, 90) {j := add(j,1)} {
        // roundConstant = H(roundConstant); we derive the (round) constants by iterative hash on the seed
        mstore(roundConstant, keccak256(roundConstant, 32))
        // a = outPermutation + roundConstant + key mod r
        a :=  addmod(addmod(outPermutation, mload(roundConstant), r), key, r)
        // a2 = a^2 mod r
        a2 := mulmod(a, a, r)
        // outPermutation = a^7 mod r (x^7 is the permutation polynomial used)
        outPermutation :=  mulmod(mulmod(mulmod(a2, a2, r), a2, r), a, r)
      }

      // Compute H_i from H_{i-1} to generate the round key for the next entry in the input slice x
      // In MiMC the output of the last round is mixed with the round key: This corresponds to the `outMiMCCipher = addmod(outPermutation, key, r)`
      // And, the Myjaguchi-Prenell OWCF is ran: `addmod(addmod(outMiMCCipher, message, r), key, r)`
      // Note that we have merged the key addition ( +key ) of the last round of MiMC with the Myjaguchi-Prenell step
      out := addmod(addmod(addmod(outPermutation, key, r), x, r), key, r)
    }

    return out;
  }
}
