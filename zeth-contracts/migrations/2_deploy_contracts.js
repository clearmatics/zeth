const MerkleTreeSha256 = artifacts.require("./MerkleTreeSha256.sol");
//const Miximus = artifacts.require("./Miximus.sol");
//const Verifier = artifacts.require("./Verifier.sol");
//const Pairing = artifacts.require("./Pairing.sol");


module.exports = (deployer) => {
  //var trusted_setup = function() {
  //  console.log("trusted_setup() start");
  //  exec('zeth setup', function(err, data) {
  //    if(err) {
  //      console.log(err);
  //      return;
  //    }
  //    console.log(data.toString());
  //  });
  //}

  //const merkle_tree_depth = 3;
  //const mixer_denomination = 2;

  deployer.deploy(MerkleTreeSha256, 3);

  // Deploy the verifier contract and then deploy Miximus
  // Retrieve the data from the trusted setup to instantiate the verifier
  //
  // Run a trusted setup to instantate the verifier contract
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
