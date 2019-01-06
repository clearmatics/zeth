const MerkleTreeSha256 = artifacts.require("./MerkleTreeSha256.sol");
//const Miximus = artifacts.require("./Miximus.sol");
//const Verifier = artifacts.require("./Verifier.sol");
//const Pairing = artifacts.require("./Pairing.sol");

module.exports = (deployer) => {
  deployer.deploy(MerkleTreeSha256, 3);

  //// Deploy the verifier contract and then deploy Miximus
  //// Retrieve the data from the trusted setup to instantiate the verifier
  ////
  //deployer.deploy(Verifier),then(function () {
  //  return deployer.deploy(Miximus, Verifier.address, 2, 3)
  //});
  //
  //deployer.deploy(Pairing);
};
