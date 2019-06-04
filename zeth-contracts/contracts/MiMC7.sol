pragma solidity ^0.5.0;

contract MiMC7 {
/*
  function MiMCHash(uint[] memory x, uint iv) public pure returns (uint h_p) {
    uint p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint x_c; //current input;
    uint seed = uint(keccak256("mimc"));
    h_p = iv; //previous hash

    for( uint i = 0; i < x.length; i++ ) {
      x_c = x[i];

      assembly {
        let c := mload(0x40)
        mstore(0x40, add(c, 32))
        mstore(c, seed)

        let h_c:= x_c
        for {let j := 0} slt(j, 91) {j := add(j,1)} {
          mstore(c, keccak256(c, 32))
          let a :=  addmod(addmod(h_c, mload(c), p), h_p, p)
          let b := mulmod(a, a, p)
          h_c :=  mulmod(mulmod(mulmod(b,b,p),b,p),a,p)
        }
        //NB: merged last round of the permutation with Myjaguchi-Prenell step
        h_p := addmod(addmod(addmod(h_c , h_p, p), x_c, p), h_p, p)
      }
    }
  }
*/
    function MiMCHash(bytes32[] memory x, bytes32 iv) public pure returns (bytes32 h_p) {
        uint p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        bytes32 x_c; //current input;
        bytes32 seed = keccak256("mimc");
        h_p = iv; //previous hash

        for( uint i = 0; i < x.length; i++ ) {
            x_c = x[i];

          assembly {
              let c := mload(0x40)
              mstore(0x40, add(c, 32))
              mstore(c, seed)

              let h_c:= x_c
              for {let j := 0} slt(j, 91) {j := add(j,1)} {
                  mstore(c, keccak256(c, 32))
                  let a :=  addmod(addmod(h_c, mload(c), p), h_p, p)
                  let b := mulmod(a, a, p)
                  h_c :=  mulmod(mulmod(mulmod(b,b,p),b,p),a,p)
              }
              //NB: merged last round of the permutation with Myjaguchi-Prenell step
              h_p := addmod(addmod(addmod(h_c , h_p, p), x_c, p), h_p, p)
          }
        }
    }
}
