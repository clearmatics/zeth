// Get verification key
var path = require('path');
var setup_path = process.env.ZETH_TRUSTED_SETUP_DIR;
var vk_json = path.join(setup_path, 'vk.json');
var vk = require(vk_json);

var tmp = []
for (var i = 0; i < vk.IC.length; i++) {
    tmp = [].concat(tmp, vk.IC[i])
}
vk.IC = tmp;

const MerkleTreeSha256 = artifacts.require("./MerkleTreeSha256.sol");
const Miximus = artifacts.require("./Miximus.sol");
const Verifier = artifacts.require("./Verifier.sol");
//const Pairing = artifacts.require("./Pairing.sol");

module.exports = (deployer) => {
  const test_merkle_tree_depth = 3;
  const test_mixer_denomination = 2;

  deployer.deploy(MerkleTreeSha256, 3);
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
    return deployer.deploy(Miximus, Verifier.address, test_mixer_denomination, test_merkle_tree_depth);
  })

  // Deploy the verifier contract and then deploy Miximus
  // Retrieve the data from the trusted setup to instantiate the verifier
  //
  // Run a trusted setup to instantiate the verifier contract
  //trusted_setup();
  //console.log("trusted_setup() start");
  //const { exec } = require('child_process');
  //exec('zeth setup', function(err, data) {
  //  if(err) {
  //    console.log(err);
  //    return;
  //  }
  //  console.log(data.toString());
  //});

  //deployer.deploy(Verifier).then(function () {
  //  return deployer.deploy(Miximus, Verifier.address, mixer_denomination, merkle_tree_depth);
  //});

  //deployer.deploy(Pairing);
};
