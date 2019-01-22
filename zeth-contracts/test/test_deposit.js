const crypto = require('crypto');
var Web3 = require('web3');

var abi = require('ethereumjs-abi');

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
  it('Test deposit 7ETH on the mixer', async () => {
    let instance = await Miximus.deployed();
    let tree_depth = 4;

    // ================== Trigger a Deposit from accounts[0] to accounts[1] ================== //
    console.log("\n===== Step1: Deposit from accounts[0] to accounts[1] (in the nullifier) =====")
    // == Inner commitment: k := COMM_r(a_pk || ρ) (in theory)
    var deposit_secret = crypto.createHash('sha256').update("test-secret-deposit").digest('hex');
    var deposit_nullifier = getNullifier(accounts[1]); // accounts[1] is the recipient
    let deposit_internal_commitment_k = crypto.createHash('sha256').
            update(Buffer.from(deposit_nullifier + deposit_secret, 'hex')).
            digest('hex');

    // == Outer commitment: cm := COMM_s(k || v)
    var deposit_trapdoor_s = crypto.createHash('sha256').update("test-trapdoor_s").digest('hex');
    var deposit_final_commitment = abi.soliditySHA256(
        [ "bytes32", "bytes32", "uint256" ],
        [ '0x' + deposit_trapdoor_s, '0x' + deposit_internal_commitment_k, web3.utils.toWei('7', 'ether') ]
    ).toString('hex');

    // We encrypt the secret with the recipient's public key
    var deposit_secret_ciphertext = encryptStringWithRsaPublicKey(deposit_secret, public_key_account_1);
    console.log("[INFO] Ciphertext of the commitment secret that is broadcasted on the network: " + deposit_secret_ciphertext);

    // --- The accounts[0] does the deposit (sender) --- //
    var accountMixer = instance.address;
    var initialBalanceMixer = await web3.eth.getBalance(accountMixer);
    assert.equal(
      initialBalanceMixer,
      web3.utils.toWei('0', 'ether'),
      "Wrong balance for the accountMixer: Should be 0"
    );

    var balance_account0_before_deposit = await web3.eth.getBalance(accounts[0]);
    var deposit_txInfo = await instance.deposit(
      deposit_secret_ciphertext,
      "0x" + deposit_final_commitment,
      "0x" + deposit_internal_commitment_k,
      "0x" + deposit_trapdoor_s,
      {from: accounts[0], value: web3.utils.toWei('7', 'ether')}
    );

		assert.equal(
      "LogAddress",
      deposit_txInfo.receipt.logs[0].event,
      "The first event emitted should be LogAddress"
    );
    assert.equal(
      "LogMerkleRoot",
      deposit_txInfo.receipt.logs[1].event,
      "The second event emitted should be LogMerkleRoot"
    );
    assert.equal(
      "LogSecretCiphers",
      deposit_txInfo.receipt.logs[2].event,
      "The third event emitted should be LogSecretCiphers"
    );

		var emitted_deposit_commitment_address = deposit_txInfo.receipt.logs[0].args["commAddr"];
    var emitted_deposit_root = stripHexPrefix(deposit_txInfo.receipt.logs[1].args["root"]);
    var emitted_deposit_ciphertext = deposit_txInfo.receipt.logs[2].args["ciphertext"];

		var balance_account0_after_deposit = await web3.eth.getBalance(accounts[0]);
    assert(
      balance_account0_after_deposit <= (balance_account0_before_deposit + Number(web3.utils.toWei('7', 'ether'))),
      "Wrong balance for the accounts[0]: Should be decreased by 2 (+ gas cost) from the initial balance"
    );

    var balance_mixer_after_deposit = await web3.eth.getBalance(accountMixer);
    assert.equal(
      balance_mixer_after_deposit,
      web3.utils.toWei('7', 'ether'),
      "Wrong balance for the accountMixer: Should be 7"
    );

    console.log("DEBUG: balance of the mixer after the deposit: " +  balance_mixer_after_deposit);
  });

  it('Test deposit 11ETH on the mixer', async () => {
    let instance = await Miximus.deployed();
    let tree_depth = 4;

    // ================== Trigger a Deposit from accounts[0] to accounts[1] ================== //
    console.log("\n===== Step1: Deposit from accounts[0] to accounts[1] (in the nullifier) =====")
    // == Inner commitment: k := COMM_r(a_pk || ρ) (in theory)
    var deposit_secret = crypto.createHash('sha256').update("test-secret-deposit").digest('hex');
    var deposit_nullifier = getNullifier(accounts[1]); // accounts[1] is the recipient
    let deposit_internal_commitment_k = crypto.createHash('sha256').
            update(Buffer.from(deposit_nullifier + deposit_secret, 'hex')).
            digest('hex');

    // == Outer commitment: cm := COMM_s(k || v)
    var deposit_trapdoor_s = crypto.createHash('sha256').update("test-trapdoor_s").digest('hex');
    var deposit_final_commitment = abi.soliditySHA256(
        [ "bytes32", "bytes32", "uint256" ],
        [ '0x' + deposit_trapdoor_s, '0x' + deposit_internal_commitment_k, web3.utils.toWei('11', 'ether') ]
    ).toString('hex');

    // We encrypt the secret with the recipient's public key
    var deposit_secret_ciphertext = encryptStringWithRsaPublicKey(deposit_secret, public_key_account_1);
    console.log("[INFO] Ciphertext of the commitment secret that is broadcasted on the network: " + deposit_secret_ciphertext);

    // --- The accounts[0] does the deposit (sender) --- //
    var accountMixer = instance.address;
    var initialBalanceMixer = await web3.eth.getBalance(accountMixer);
    assert.equal(
      initialBalanceMixer,
      web3.utils.toWei('7', 'ether'),
      "Wrong balance for the accountMixer: Should be 0"
    );

    var balance_account0_before_deposit = await web3.eth.getBalance(accounts[0]);
    var deposit_txInfo = await instance.deposit(
      deposit_secret_ciphertext,
      "0x" + deposit_final_commitment,
      "0x" + deposit_internal_commitment_k,
      "0x" + deposit_trapdoor_s,
      {from: accounts[0], value: web3.utils.toWei('11', 'ether')}
    );

		assert.equal(
      "LogAddress",
      deposit_txInfo.receipt.logs[0].event,
      "The first event emitted should be LogAddress"
    );
    assert.equal(
      "LogMerkleRoot",
      deposit_txInfo.receipt.logs[1].event,
      "The second event emitted should be LogMerkleRoot"
    );
    assert.equal(
      "LogSecretCiphers",
      deposit_txInfo.receipt.logs[2].event,
      "The third event emitted should be LogSecretCiphers"
    );

		var emitted_deposit_commitment_address = deposit_txInfo.receipt.logs[0].args["commAddr"];
    var emitted_deposit_root = stripHexPrefix(deposit_txInfo.receipt.logs[1].args["root"]);
    var emitted_deposit_ciphertext = deposit_txInfo.receipt.logs[2].args["ciphertext"];

		var balance_account0_after_deposit = await web3.eth.getBalance(accounts[0]);
    assert(
      balance_account0_after_deposit <= (balance_account0_before_deposit + Number(web3.utils.toWei('11', 'ether'))),
      "Wrong balance for the accounts[0]: Should be decreased by 11 (+ gas cost) from the initial balance"
    );

    var balance_mixer_after_deposit = await web3.eth.getBalance(accountMixer);
    assert.equal(
      balance_mixer_after_deposit,
      web3.utils.toWei('18', 'ether'),
      "Wrong balance for the accountMixer: Should be 11"
    );

    console.log("DEBUG: balance of the mixer after the deposit: " +  balance_mixer_after_deposit);
  });
});
