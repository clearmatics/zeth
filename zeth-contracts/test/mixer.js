const crypto = require('crypto');
var Web3 = require('web3');

const stripHexPrefix = require('strip-hex-prefix');
const shellescape = require('shell-escape');
const fs = require('fs');

const { execSync } = require('child_process');

const MerkleTreeSha256 = artifacts.require("./MerkleTreeSha256.sol");
const Miximus = artifacts.require("./Miximus.sol");
const Verifier = artifacts.require("./Verifier.sol");
const Pairing = artifacts.require("./Pairing.sol");

const path = require("path");
const debug_path = process.env.ZETH_DEBUG_DIR;
const extended_proof_json = path.join(debug_path, 'proof_and_input.json');

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
  it('Test deposit-transfer-withdrawal on the mixer', async () => {
    let instance = await Miximus.deployed();
    let tree_depth = 4; // need to match the tree depth that is used to instantiate the cli (tree depth we used for the trsuted setup)

    // ================== Trigger a Deposit from accounts[0] to accounts[1] ================== //
    console.log("\n===== Step1: Deposit from accounts[0] to accounts[1] (in the nullifier) =====")
    // We insert at the first available leaf (leftmost leaf --> index 7 in the tree of depth 3)
    var deposit_secret = crypto.createHash('sha256').update("test-secret-deposit").digest('hex');
    var deposit_nullifier = getNullifier(accounts[1]); // accounts[1] is the recipient
    let deposit_commitment = crypto.createHash('sha256').
            update(Buffer.from(deposit_nullifier + deposit_secret, 'hex')).
            digest('hex');

    // We encrypt the secret with the recipient's public key
    var deposit_secret_ciphertext = encryptStringWithRsaPublicKey(deposit_secret, public_key_account_1);
    console.log("[INFO] Ciphertext of the commitment secret that is broadcasted on the network: " + deposit_secret_ciphertext);

    // --- The accounts[0] does the deposit (sender) --- //
    // We have a mixer of std denom of 2 ether --> see migration file
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
      "0x" + deposit_commitment,
      {from: accounts[0], value: web3.utils.toWei('2', 'ether')}
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
      balance_account0_after_deposit <= (balance_account0_before_deposit + Number(web3.utils.toWei('2', 'ether'))),
      "Wrong balance for the accounts[0]: Should be decreased by 2 (+ gas cost) from the initial balance"
    );

    var balance_mixer_after_deposit = await web3.eth.getBalance(accountMixer);
    assert.equal(
      balance_mixer_after_deposit,
      web3.utils.toWei('2', 'ether'),
      "Wrong balance for the accountMixer: Should be 2"
    );

    // Get the merkle tree after insertion to generate the proof
    let deposit_tree = await instance.getTree({from: accounts[2]});
    for(var i = 0; i < deposit_tree.length; i++) {
      console.log("Node(" + i + ") =>" + deposit_tree[i]);
    }

    let deposit_root = stripHexPrefix(deposit_tree[0]);
    console.log("Root => " + deposit_root);

    let deposit_commitment_inserted = deposit_tree[15];
    console.log("Commitment inserted => " + deposit_commitment_inserted);
    assert.equal(
      stripHexPrefix(deposit_commitment_inserted),
      deposit_commitment,
      "The commitment read from the tree should be equal to the one appended"
    )

    // Get merkle root and merkle path for the commitment at node 16 in the tree
    // (The address of the commitment is 0 since the address is relative to the leaves array)
    let deposit_node16 = stripHexPrefix(deposit_tree[16]); // We update the merkle path to work with the new appended commitment (address = 1 here, not 0 anymore)
    let deposit_node8 = stripHexPrefix(deposit_tree[8]);
    let deposit_node4 = stripHexPrefix(deposit_tree[4]);
    let deposit_node2 = stripHexPrefix(deposit_tree[2]);
    let deposit_address = 0; // The commitment should be appended to the address 1 in the tree (address 0 is taken by commitment in previous test)

		// Assert the theoretical values with the various values read from the events emitted after depositing the funds
    assert.equal(
      emitted_deposit_commitment_address,
      deposit_address,
      "The commitment address emitted is invalid"
    );
    assert.equal(
      emitted_deposit_root,
      deposit_root,
      "The root emitted is invalid"
    );
    assert.equal(
      emitted_deposit_ciphertext,
      deposit_secret_ciphertext,
      "The ciphertext emitted is invalid"
    );

		// The intended recipient (accounts[1]) decrypts the ciphertext to get the commitment secret to generate the proof
    var deposit_decrypted_secret = decryptStringWithRsaPrivateKey(emitted_deposit_ciphertext, private_key_account_1);

    // Invoke the CLI prove command
    zethProve(["prove", tree_depth, emitted_deposit_commitment_address, deposit_decrypted_secret, deposit_nullifier, deposit_commitment, emitted_deposit_root, deposit_node2, deposit_node4, deposit_node8, deposit_node16]);

    // We read the proof provided as argument to the transfer call
    //var transfer_extended_proof = require(extended_proof_json);
    var transfer_extended_proof = JSON.parse(fs.readFileSync(extended_proof_json, 'utf8'));

    // --- The accounts[1] does the transfer to accounts[2] (recipient) --- //
		console.log("\n ===== Step2: Accounts[1] does a transfer() to accounts[2] ====== ");
		var transfer_secret = crypto.createHash('sha256').update("test-secret-transfer").digest('hex');
    var transfer_nullifier = getNullifier(accounts[2]); // accounts[2] is the recipient
    let transfer_commitment = crypto.createHash('sha256').
            update(Buffer.from(transfer_nullifier + transfer_secret, 'hex')).
            digest('hex');

		// We encrypt the secret with the recipient's public key (recipient = accounts[2] here)
		var transfer_secret_ciphertext = encryptStringWithRsaPublicKey(transfer_secret, public_key_account_2);
    console.log("[INFO] Ciphertext of the commitment secret that is broadcasted on the network after the transfer call: " + transfer_secret_ciphertext);

    var balance_account1_before_transfer = await web3.eth.getBalance(accounts[1]);
    var transfer_txInfo = await instance.transfer(
      transfer_secret_ciphertext,
			"0x" + transfer_commitment,
      transfer_extended_proof.a,
      transfer_extended_proof.a_p,
      transfer_extended_proof.b,
      transfer_extended_proof.b_p,
      transfer_extended_proof.c,
      transfer_extended_proof.c_p,
      transfer_extended_proof.h,
      transfer_extended_proof.k,
      transfer_extended_proof.input,
      {from: accounts[1]}
    );
    var balance_account1_after_transfer = await web3.eth.getBalance(accounts[1]);
    assert(
      balance_account1_after_transfer <= balance_account1_before_transfer,
      "Wrong balance for the accounts[1]: Should be decreased by the gas cost of the transfer function"
    );

		// Make sure that the Mixer still has 2 ether in his balance after the call to the transfer function
    var balance_mixer_after_transfer = await web3.eth.getBalance(accountMixer);
    assert.equal(
      balance_mixer_after_transfer,
      web3.utils.toWei('2', 'ether'),
      "Wrong balance for the accountMixer: Should be 2"
    );

		// Get the events emitted during the call to the transfer function (contains the ciphertext of the commitment secret)
    assert.equal(
      "LogAddress",
      transfer_txInfo.receipt.logs[0].event,
      "The first event emitted should be LogAddress"
    );
    assert.equal(
      "LogMerkleRoot",
      transfer_txInfo.receipt.logs[1].event,
      "The second event emitted should be LogMerkleRoot"
    );
    assert.equal(
      "LogSecretCiphers",
      transfer_txInfo.receipt.logs[2].event,
      "The third event emitted should be LogSecretCiphers"
    );

		var transfer_emitted_commitment_address = transfer_txInfo.receipt.logs[0].args["commAddr"];
    var transfer_emitted_root = stripHexPrefix(transfer_txInfo.receipt.logs[1].args["root"]); // Strip the "0x" prefix of hex strings
    var transfer_emitted_ciphertext = transfer_txInfo.receipt.logs[2].args["ciphertext"];

    // Get the merkle tree after insertion to generate the proof
    let transfer_tree = await instance.getTree({from: accounts[2]});
    for(var i = 0; i < transfer_tree.length; i++) {
      console.log("Node(" + i + ") =>" + transfer_tree[i]);
    }

    let transfer_root = stripHexPrefix(transfer_tree[0]);
    console.log("Root => " + transfer_root);

    let transfer_commitment_inserted = transfer_tree[16];
    console.log("Commitment inserted => " + transfer_commitment_inserted);
    assert.equal(
      stripHexPrefix(transfer_commitment_inserted),
      transfer_commitment,
      "The commitment read from the tree should be equal to the one appended"
    )

    // Get merkle root and merkle path for the commitment at node 15 in the tree
    // (The address of the commitment is 0 since the address is relative to the leaves array)
    let transfer_node15 = stripHexPrefix(transfer_tree[15]);
    let transfer_node8 = stripHexPrefix(transfer_tree[8]);
    let transfer_node4 = stripHexPrefix(transfer_tree[4]);
    let transfer_node2 = stripHexPrefix(transfer_tree[2]);
    let transfer_address = 1;

    // Assert the theoretical values with the various values read from the events emitted after depositing the funds
    assert.equal(
      transfer_emitted_commitment_address,
      transfer_address,
      "The commitment address emitted is invalid"
    );
    assert.equal(
      transfer_emitted_root,
      transfer_root,
      "The root emitted is invalid"
    );
    assert.equal(
      transfer_emitted_ciphertext,
      transfer_secret_ciphertext,
      "The ciphertext emitted is invalid"
    );

    // The intended recipient (accounts[1]) decrypts the ciphertext to get the commitment secret to generate the proof
    var transfer_decrypted_secret = decryptStringWithRsaPrivateKey(transfer_emitted_ciphertext, private_key_account_2);

    // Invoke the CLI prove command
		// This command takes the secret as one of the input, which is only accessible via the encrypted boradcast
		// That can only be decrypted by the owner of the private key associated to the public key used to encrypt
		// (intended recipient of the payment)
    zethProve(["prove", tree_depth, transfer_emitted_commitment_address, transfer_decrypted_secret, transfer_nullifier, transfer_commitment, transfer_emitted_root, transfer_node2, transfer_node4, transfer_node8, transfer_node15]);

    // Read the proof provided as input for the withdrawal
    //var withdraw_extended_proof = require(extended_proof_json);
    var withdraw_extended_proof = JSON.parse(fs.readFileSync(extended_proof_json, 'utf8'));

		// =================== Now we need to withdraw from accounts[2] account ==================== //
		console.log("\n ===== Step3: Accounts[2] does a withdrawal and gets his balance updated =====");
    var balance_account2_before_withdraw = await web3.eth.getBalance(accounts[2]);
    var withdraw_txInfo = await instance.withdraw(
      withdraw_extended_proof.a,
      withdraw_extended_proof.a_p,
      withdraw_extended_proof.b,
      withdraw_extended_proof.b_p,
      withdraw_extended_proof.c,
      withdraw_extended_proof.c_p,
      withdraw_extended_proof.h,
      withdraw_extended_proof.k,
      withdraw_extended_proof.input,
      {from: accounts[2]}
    );
    var balance_account2_after_withdraw = await web3.eth.getBalance(accounts[2]);

    // Get the gas cost of the withdrawal function to do a precise assert
    assert(
      balance_account2_after_withdraw > balance_account2_before_withdraw,
      "Wrong balance for the accounts[2]: Should be increased by 2 (minus the gas cost) from the initial balance"
    );

    var balance_mixer_after_withdrawal = await web3.eth.getBalance(accountMixer);
    assert.equal(
      balance_mixer_after_withdrawal,
      web3.utils.toWei('0', 'ether'),
      "Wrong balance for the accountMixer: Should be 0"
    );
  });
});
