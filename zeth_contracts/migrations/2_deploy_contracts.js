// Get verification key
var path = require('path');
var setup_path = process.env.ZETH_SETUP_DIR;
var vk_json = path.join(setup_path, 'vk.json');
var vk = require(vk_json);

var tmp = []
for (var i = 0; i < vk.IC.length; i++) {
    tmp = [].concat(tmp, vk.IC[i])
}
vk.IC = tmp;

const MerkleTreeSha256 = artifacts.require("./MerkleTreeSha256.sol");
const Mixer = artifacts.require("./Mixer.sol");
const Verifier = artifacts.require("./Verifier.sol");
const Bytes = artifacts.require("./Bytes.sol");
const Bytes_tests = artifacts.require("./Bytes_tests.sol");

module.exports = (deployer) => {
  console.log("[WARNING] Make sure you have the right verification key stored in the `ZETH_SETUP_DIR`!")
  deployer.deploy(
    Verifier,
    vk.a[0],
    vk.a[1],
    vk.b,
    vk.c[0],
    vk.c[1],
    vk.g[0],
    vk.g[1],
    vk.gb1,
    vk.gb2[0],
    vk.gb2[1],
    vk.z[0],
    vk.z[1],
    vk.IC
  ).then(function () {
    // We deploy a mixer with a merkle tree of depth 4
    return deployer.deploy(Mixer, Verifier.address, 4);
  })

  deployer.deploy(Bytes);
  deployer.link(Bytes, Bytes_tests);
  deployer.deploy(Bytes_tests);

  // Deploy a merkle tree of depth 3 for the tests
  deployer.deploy(MerkleTreeSha256, 3);
};
