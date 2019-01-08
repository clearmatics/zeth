const crypto = require('crypto');
var Web3 = require('web3');
var path = require("path");

const stripHexPrefix = require('strip-hex-prefix');
const shellescape = require('shell-escape');
const fs = require('fs');

const { execSync } = require('child_process');

const MerkleTreeSha256 = artifacts.require("./MerkleTreeSha256.sol");
const Miximus = artifacts.require("./Miximus.sol");
const Verifier = artifacts.require("./Verifier.sol");
const Pairing = artifacts.require("./Pairing.sol");

function prefixHexadecimalString(hex_str) {
  return "0x" + hex_str;
}

const public_key_account_1 = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDP34BAdxAX0p9yxhcoqkQtCKWc
o/t/MEqLfjCP/dwkrN9MmML4CGYXqF0X9UKxv+2qxhtxkLLFtPnyT6PRTQDnPuHw
+D8kQ4DOyn5fBVpIwvPVl/COIZYiSQgv2YaE8UI/9YtXLE9njJItsCJQbtcKY6TZ
8JmIxk2E9fNah9V+SQIDAQAB
-----END PUBLIC KEY-----`;

const private_key_account_1 = `-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgQDP34BAdxAX0p9yxhcoqkQtCKWco/t/MEqLfjCP/dwkrN9MmML4
CGYXqF0X9UKxv+2qxhtxkLLFtPnyT6PRTQDnPuHw+D8kQ4DOyn5fBVpIwvPVl/CO
IZYiSQgv2YaE8UI/9YtXLE9njJItsCJQbtcKY6TZ8JmIxk2E9fNah9V+SQIDAQAB
An92hzpoMl86xHOmk3fLv0pnnCon5wOkF7NNVspoM+2hGGM7F/xM8Zl98hfNpr1Z
q2TEEM6G+fPZZFEEfToPJSdzAf1GUPBNeIr/iJCERM1UzlRb1C09jil1Spne3NSa
xYx3JVZs2WEhz/RAELuRzMBqntDNYmbUhhPEZ3S4WIBNAkEA3KvB1JvmJp5+S72S
7JGsiH3iP0q/MsyLdZFyOtBiUlcmJ67iTDPR/sTF/o4jZrFQf8heGDRzvgLbqxbz
NsIy1QJBAPEnOGUs8qo8JsIQv7khx3HDXO1pVA4WfL9i+G9AQKUtbN0pi8kErBCy
KShUEsQQfx69r2BkUO/mxXuTKUKPT6UCQEQ8FBaTEmq0rabr+seOEASwsEoT6eVi
XGlBTUokb5K4ggLZT/5yM6gM3pBlEUtK3vJ0WawwY+3IYnaYBSLUj/UCQFeK5Fce
RQ11fqBukhrz30I2KJLq7J+cnDaiCAvi6FTOM7nprhwQPSJmerhwJMvWLT+MnpDA
ef1M6h3dI1pNSh0CQQCjEQ/5Udy3YjQQfE1f+sW2CnosVGP7VZFhVyAT+KBxm8Sh
YnR+rry8uG5XUjjkxOVoRDEZMx2uErlklDhYy4r0
-----END RSA PRIVATE KEY-----`;

const public_key_account_2 = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCNOiZl4N22xoX+utRrKvUoirhZ
74ZEefTy0MkoBsi9rsjVkqh0GAnWNOyL35t0BaQLSsiUDMmlzhTvoo8eIiixTaEz
z4l/XrQi4OcdUMtNgIKEBpwwwLqzT5eaiywncAueCz8NuB3TZBVN3FrTRLOWjFdu
x4USibpT1bcBRyqb2QIDAQAB
-----END PUBLIC KEY-----`;

const private_key_account_2 = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCNOiZl4N22xoX+utRrKvUoirhZ74ZEefTy0MkoBsi9rsjVkqh0
GAnWNOyL35t0BaQLSsiUDMmlzhTvoo8eIiixTaEzz4l/XrQi4OcdUMtNgIKEBpww
wLqzT5eaiywncAueCz8NuB3TZBVN3FrTRLOWjFdux4USibpT1bcBRyqb2QIDAQAB
AoGAE1N40Qo+QkvVJwWuxIztXZiWH7XicYPK8bYr64P6Jn2WUtEDUle+c4dsiLuX
If+/nM1QDh/Yhw22LxDXdZqGZ4DpDDZnkD1ZJFQbu3t+I5AthAuxxoV3EThIcAvF
oy3DES3g0/3zDqGlruXqy2vjDO+50xx+8anjAR7SKtTVva0CQQC3zQ33QVddUlX4
ubW4q1+/M851hpkbSIYqL1FhWUKgcd7NnxWkFfAxfixwyWSPGTJaHCtz5V/Yb5v+
172tpMsLAkEAxLPje++hNaCW37USNceGDVH52+8i4Z7vJ9pcW8u/3MpyP0ovldn9
YbfunLi9FWyetchbAA/WN3s3Nipuwm4jKwJBAIR7yrBJqfZ7bbqt6d2lsYs5hXzT
OzMeUI7BsrAvzcWmromaPNgcdBjIsLHPiKtY5yFqoquUT0TMFi5YRcGPQkcCQHcz
WCDL55Ka/bMVhLKIdejui47HTQkTCnTJM/0A7QT8vd0ytMGHt7AXCYd5wEQSbd9V
SigwcK1wgtXVQweaPL8CQGQEyIwe5VjgnLOxgZhW6MFmjaKTNZGmf8wbxwgmbId2
V9y86vlqTVc+U24dBM6uq5ncznGodmrOwhj0i3vUteU=
-----END RSA PRIVATE KEY-----`;

var encryptStringWithRsaPublicKey = function(toEncrypt, public_key) {
	var buffer = new Buffer(toEncrypt);
	var encrypted = crypto.publicEncrypt(public_key, buffer);
	return encrypted.toString("base64");
};

var decryptStringWithRsaPrivateKey = function(toDecrypt, private_key) {
	var buffer = new Buffer(toDecrypt, "base64");
	var decrypted = crypto.privateDecrypt(private_key, buffer);
	return decrypted.toString("utf8");
};

if (typeof web3 !== 'undefined') {
  web3 = new Web3(web3.currentProvider);
} else {
  // Set the provider you want from Web3.providers
  web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"))
}

function getNullifier(recipientAddr) {
  var hardcoded_salt = "FFFFFFFFFFFFFFFFFFFFFFFA"; // For testing purpose obviously
  var nullifier = stripHexPrefix(recipientAddr + hardcoded_salt);
  console.log("[INFO] Nullifier: " + nullifier);
  return nullifier;
}

// --- Wrapper arounf the zeth CLI --- //
function zethProve(args) {
  var cmd_str = shellescape(["zeth"].concat(args)).toString().trim("\n");
  console.log("[INFO] Running command: " + cmd_str);
  return execSync(shellescape(["zeth"].concat(args))).toString().trim("\n");
}

contract('Miximus', (accounts) => {
  it('Test deposit-withdrawal on the mixer', async () => {
    // We have a merkle tree of depth 3 for the tests
    let instance = await Miximus.deployed();

    console.log("Accounts[0] deposits a commitment for Accounts[1], and Accounts[1] withdraws");

    // --- Leaves layer (layer 3) --- //
    // We insert at the first available leaf (leftmost leaf --> index 7 in the tree of depth 3)
    var secret = crypto.createHash('sha256').update("test-secret").digest('hex');
    var nullifier = getNullifier(accounts[1]); // accounts[1] is the recipient
    let commitment = crypto.createHash('sha256').
            update(Buffer.from(nullifier + secret, 'hex')).
            digest('hex');

		// We encrypt the secret with the recipient's public key
		var secret_ciphertext = encryptStringWithRsaPublicKey(secret, public_key_account_1);
    console.log("[INFO] Ciphertext of the commitment secret that is broadcasted on the network: " + secret_ciphertext);

    // --- The accounts[0] does the deposit (sender) --- //
    // We have a mixer of std denom of 2 ether --> see migration file
    var account0 = accounts[0];
    var accountMixer = instance.address;
    var initialBalanceMixer = await web3.eth.getBalance(accountMixer);
    assert.equal(
      initialBalanceMixer,
      web3.utils.toWei('0', 'ether'),
      "Wrong balance for the accountMixer: Should be 0"
    );

    var initialBalanceAccount0 = await web3.eth.getBalance(account0);
    var txInfo = await instance.deposit(
			secret_ciphertext,
			"0x" + commitment,
			{from: account0, value: web3.utils.toWei('2', 'ether')}
		);

    // Get the events emitted during the deposit (contains the ciphertext of the commitment secret)
    assert.equal(
      "LogAddress",
      txInfo.receipt.logs[0].event,
      "The first event emitted should be LogAddress"
    );
    assert.equal(
      "LogMerkleRoot",
      txInfo.receipt.logs[1].event,
      "The second event emitted should be LogMerkleRoot"
    );
    assert.equal(
      "LogSecretCiphers",
      txInfo.receipt.logs[2].event,
      "The third event emitted should be LogSecretCiphers"
    );

    var emitted_commitment_address = txInfo.receipt.logs[0].args["commAddr"];
    var emitted_root = stripHexPrefix(txInfo.receipt.logs[1].args["root"]);
    var emitted_ciphertext = txInfo.receipt.logs[2].args["ciphertext"];

    var balanceAccount0 = await web3.eth.getBalance(account0);
    // Get the gas cost of the deposit function to do a precise assert
    var tx = await web3.eth.getTransaction(txInfo.tx);
    var gasCost = (tx.gasPrice) * (txInfo.receipt.gasUsed);
    assert.equal(
      balanceAccount0,
      initialBalanceAccount0 - (Number(web3.utils.toWei('2', 'ether')) + gasCost),
      "Wrong balance for the account0: Should be decreased by 2 from the initial balance"
    );

    var balanceMixerAfterDeposit = await web3.eth.getBalance(accountMixer);
    assert.equal(
      balanceMixerAfterDeposit,
      web3.utils.toWei('2', 'ether'),
      "Wrong balance for the accountMixer: Should be 2"
    );

    // Get the merkle tree after insertion to generate the proof
    let tree = await instance.getTree({from: accounts[2]});
    for(var i = 0; i < tree.length; i++) {
      console.log("Node(" + i + ") =>" + tree[i]);
    }
    let root = stripHexPrefix(tree[0]);
    console.log("Root => " + root);
    let commitment_inserted = tree[15];
    console.log("Commitment inserted => " + commitment_inserted);
    assert.equal(
      stripHexPrefix(commitment_inserted),
      commitment,
      "The commitment read from the tree should be equal to the one appended"
    )

    // Get merkle root and merkle path for the commitment at node 15 in the tree
    // (The address of the commitment is 0 since the address is relative to the leaves array)
    let node16 = stripHexPrefix(tree[16]);
    let node8= stripHexPrefix(tree[8]);
    let node4= stripHexPrefix(tree[4]);
    let node2 = stripHexPrefix(tree[2]);
    let tree_depth = 4; // need to match the tree depth that is used to instantiate the cli (tree depth we used for the trsuted setup)
    let address = 0;

    // Assert the theoretical values with the various values read from the events emitted after depositing the funds
    assert.equal(
      emitted_commitment_address,
      address,
      "The commitment address emitted is invalid"
    );
    assert.equal(
      emitted_root,
      root,
      "The root emitted is invalid"
    );
    assert.equal(
      emitted_ciphertext,
      secret_ciphertext,
      "The ciphertext emitted is invalid"
    );

    // The intended recipient (accounts[1]) decrypts the ciphertext to get the commitment secret to generate the proof
    var decrypted_secret = decryptStringWithRsaPrivateKey(emitted_ciphertext, private_key_account_1);

    // Invoke the CLI prove command
		// This command takes the secret as one of the input, which is only accessible via the encrypted boradcast
		// That can only be decrypted by the owner of the private key associated to the public key used to encrypt
		// (intended recipient of the payment)
    zethProve(["prove", tree_depth, emitted_commitment_address, secret, nullifier, commitment, emitted_root, node2, node4, node8, node16]);

    var path = require('path');
    var debug_path = process.env.ZETH_DEBUG_DIR;
    var extended_proof_json = path.join(debug_path, 'proof_and_input.json');
    var extended_proof = require(extended_proof_json);

    // --- The accounts[1] does the withdrawal (recipient) --- //
    var account1 = accounts[1];
    var initialBalanceAccount1 = await web3.eth.getBalance(account1);
    txInfo = await instance.withdraw(
      extended_proof.a,
      extended_proof.a_p,
      extended_proof.b,
      extended_proof.b_p,
      extended_proof.c,
      extended_proof.c_p,
      extended_proof.h,
      extended_proof.k,
      extended_proof.input,
      {from: account1}
    );
    var balanceAccount1 = await web3.eth.getBalance(account1);

    // Get the gas cost of the withdrawal function to do a precise assert
    tx = await web3.eth.getTransaction(txInfo.tx);
    gasCost = (tx.gasPrice) * (txInfo.receipt.gasUsed);
    assert.equal(
      balanceAccount1,
      (initialBalanceAccount1 - gasCost) + Number(web3.utils.toWei('2', 'ether')),
      "Wrong balance for the account1: Should be increased by 2 from the initial balance"
    );

    var balanceMixerAfterWithdrawal = await web3.eth.getBalance(accountMixer);
    assert.equal(
      balanceMixerAfterWithdrawal,
      web3.utils.toWei('0', 'ether'),
      "Wrong balance for the accountMixer: Should be 0"
    );
  });

  //it('Test deposit-transfer-withdrawal on the mixer', async () => {
  //  // We have a merkle tree of depth 3 for the tests
  //  let instance = await Miximus.deployed();

  //  // --- Leaves layer (layer 3) --- //
  //  console.log("Step1: Deposit from accounts[0] to accounts[1] (in the nullifier)")
  //  // We insert at the first available leaf (leftmost leaf --> index 7 in the tree of depth 3)
  //  var secret_1 = crypto.createHash('sha256').update("test-secret").digest('hex');
  //  var nullifier_1 = getNullifier(accounts[1]); // accounts[1] is the recipient
  //  let commitment_1 = crypto.createHash('sha256').
  //          update(Buffer.from(nullifier_1 + secret_1, 'hex')).
  //          digest('hex');

  //  // --- The accounts[0] does the deposit (sender) --- //
  //  // We have a mixer of std denom of 2 ether --> see migration file
  //  var account0 = accounts[0];
  //  var accountMixer = instance.address;
  //  var initialBalanceMixer = await web3.eth.getBalance(accountMixer);
  //  assert.equal(
  //    initialBalanceMixer,
  //    web3.utils.toWei('0', 'ether'),
  //    "Wrong balance for the accountMixer: Should be 0"
  //  );

  //  var initialBalanceAccount0 = await web3.eth.getBalance(account0);
  //  var txInfo = await instance.deposit("0x" + commitment, {from: account0, value: web3.utils.toWei('2', 'ether')});
  //  var balanceAccount0 = await web3.eth.getBalance(account0);
  //  // Get the gas cost of the deposit function to do a precise assert
  //  var tx = await web3.eth.getTransaction(txInfo.tx);
  //  var gasCost = (tx.gasPrice) * (txInfo.receipt.gasUsed);
  //  assert.equal(
  //    balanceAccount0,
  //    initialBalanceAccount0 - (Number(web3.utils.toWei('2', 'ether')) + gasCost),
  //    "Wrong balance for the account0: Should be decreased by 2 from the initial balance"
  //  );

  //  var balanceMixerAfterDeposit = await web3.eth.getBalance(accountMixer);
  //  assert.equal(
  //    balanceMixerAfterDeposit,
  //    web3.utils.toWei('2', 'ether'),
  //    "Wrong balance for the accountMixer: Should be 2"
  //  );

  //  // Get the merkle tree after insertion to generate the proof
  //  let tree = await instance.getTree({from: accounts[2]});
  //  for(var i = 0; i < tree.length; i++) {
  //    console.log("Node(" + i + ") =>" + tree[i]);
  //  }
  //  let root = stripHexPrefix(tree[0]);
  //  console.log("Root => " + root);
  //  let commitment_inserted = tree[15];
  //  console.log("Commitment inserted => " + commitment_inserted);
  //  assert.equal(
  //    stripHexPrefix(commitment_inserted),
  //    commitment,
  //    "The commitment read from the tree should be equal to the one appended"
  //  )

  //  // Get merkle root and merkle path for the commitment at node 15 in the tree
  //  // (The address of the commitment is 0 since the address is relative to the leaves array)
  //  let node16 = stripHexPrefix(tree[16]);
  //  let node8= stripHexPrefix(tree[8]);
  //  let node4= stripHexPrefix(tree[4]);
  //  let node2 = stripHexPrefix(tree[2]);
  //  let tree_depth = 4; // need to match the tree depth that is used to instantiate the cli (tree depth we used for the trsuted setup)
  //  let address = 1; // The commitment should be appended to the address 1 in the tree

  //  // Invoke the CLI prove command
  //  zethProve(["prove", tree_depth, address, secret, nullifier, commitment, root, node2, node4, node8, node16]);

  //  var path = require('path');
  //  var debug_path = process.env.ZETH_DEBUG_DIR;
  //  var extended_proof_json = path.join(debug_path, 'proof_and_input.json');
  //  var extended_proof = require(extended_proof_json);

  //  // --- The accounts[1] does the withdrawal (recipient) --- //
  //  var account1 = accounts[1];
  //  var initialBalanceAccount1 = await web3.eth.getBalance(account1);
  //  txInfo = await instance.forward(
  //    ciphertext_secret
  //    extended_proof.a,
  //    extended_proof.a_p,
  //    extended_proof.b,
  //    extended_proof.b_p,
  //    extended_proof.c,
  //    extended_proof.c_p,
  //    extended_proof.h,
  //    extended_proof.k,
  //    extended_proof.input,
  //    {from: account1}
  //  );
  //  var balanceAccount1 = await web3.eth.getBalance(account1);

  //  // Get the gas cost of the withdrawal function to do a precise assert
  //  tx = await web3.eth.getTransaction(txInfo.tx);
  //  gasCost = (tx.gasPrice) * (txInfo.receipt.gasUsed);
  //  assert.equal(
  //    balanceAccount1,
  //    (initialBalanceAccount1 - gasCost) + Number(web3.utils.toWei('2', 'ether')),
  //    "Wrong balance for the account1: Should be increased by 2 from the initial balance"
  //  );

  //  var balanceMixerAfterWithdrawal = await web3.eth.getBalance(accountMixer);
  //  assert.equal(
  //    balanceMixerAfterWithdrawal,
  //    web3.utils.toWei('0', 'ether'),
  //    "Wrong balance for the accountMixer: Should be 0"
  //  );
  //});
});
