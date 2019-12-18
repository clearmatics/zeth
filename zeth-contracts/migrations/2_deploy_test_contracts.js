const MerkleTreeSha256 = artifacts.require("./MerkleTreeSha256.sol");
const Bytes = artifacts.require("./Bytes.sol");
const Bytes_tests = artifacts.require("./Bytes_tests.sol");

module.exports = (deployer) => {
  deployer.deploy(Bytes);
  deployer.link(Bytes, Bytes_tests);
  deployer.deploy(Bytes_tests);

  // Deploy a merkle tree of depth 3 for the tests
  deployer.deploy(MerkleTreeSha256, 3);
};
