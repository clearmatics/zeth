const crypto = require('crypto');
const NodeRSA = require('node-rsa');
const abi = require('ethereumjs-abi');
const Web3 = require('web3');

if (typeof web3 !== 'undefined') {
  web3 = new Web3(web3.currentProvider);
} else {
  // Set the provider you want from Web3.providers
  web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"))
}

var noteRandomness = function() {
  const rand_rho = crypto.randomBytes(32).toString('hex');
  const rand_trapR = crypto.randomBytes(48).toString('hex');

  return {
    rho: rand_rho,
    trapR: rand_trapR
  };
};

// We follow the formatting of the proto file
var createZethNote = function(randomness, recipientApk, value) {
  return {
    aPK: recipientApk,
    value: value,
    rho: randomness.rho,
    trapR: randomness.trapR
  };
};

var hexFmt = function(str) {
  return "0x" + str;
};

var computeCommitment = function(zethNote) {
  // inner_k = sha256(a_pk || rho)
  var inner_k = abi.soliditySHA256(
    ["bytes32", "bytes32"],
    [hexFmt(zethNote.apk), hexFmt(zethNote.rho)]
  ).toString('hex');

  // outer_k = sha256(r || [inner_commitment]_128)
  var first128InnerComm = inner_k.substring(0, 128);
  var outer_k = abi.soliditySHA256(
    ["string", "string"],
    [hexFmt(zethNote.trapR), hexFmt(first128InnerComm)]
  ).toString('hex');

  // cm = sha256(outer_k || 0^192 || value_v)
  var frontPaddedValue = "000000000000000000000000000000000000000000000000";
  var cm = abi.soliditySHA256(
    ["bytes32", "bytes32"],
    [hexFmt(outer_k), hexFmt(first128InnerComm)]
  ).toString('hex');

  return cm;
};

var computeNullifier = function(zethNote, spendingAuthAsk) {
  // nf = sha256(a_sk || 01 || [rho]_254)
  var first254Rho = zethNote.rho.substring(0, 254);
  var rightLeg = "01" + first254Rho;
  var nullifier = abi.soliditySHA256(
    ["bytes32", "bytes32"],
    [hexFmt(spendingAuthAsk), hexFmt(rightLeg)]
  ).toString('hex');

  return nullifier;
}

var decimalToHexadecimal = function(str) {
  var dec = str.toString().split(''), sum = [], hex = [], i, s
  while(dec.length){
    s = 1 * dec.shift()
    for(i = 0; s || i < sum.length; i++){
      s += (sum[i] || 0) * 10
      sum[i] = s % 16
      s = (s - sum[i]) / 16
    }
  }
  while(sum.length){
    hex.push(sum.pop().toString(16))
  }
  return hex.join('')
};

var deriveAPK = function(ask) {
  // a_pk = sha256(a_sk || 0^256)
  var zeroes = "0000000000000000000000000000000000000000000000000000000000000000";
  var a_pk = abi.soliditySHA256(
    ["bytes32", "bytes32"],
    [hexFmt(ask), hexFmt(zeroes)]
  ).toString('hex');

  return a_pk;
};

var generateApkAskKeypair = function() {
  const a_sk = crypto.randomBytes(32).toString('hex');
  const a_pk = deriveAPK(a_sk);

  return {
    a_sk: a_sk,
    a_pk: a_pk
  };
};

var createJSInput = function(merklePath, address, note, ask, nullifier) {
  return {
    merkleNode: merklePath,
    address: address,
    note: note,
    spendingASK: ask,
    nullifier: nullifier
  };
}

var parseHexadecimalPointBaseGroup1Affine = function(point) {
  return [point.xCoord, point.yCoord];
}

var parseHexadecimalPointBaseGroup2Affine =  function(point) {
  return [
    [point.xC1Coord, point.xC0Coord],
    [point.yC1Coord, point.yC0Coord]
  ];
}

// Keystore for the tests
var initTestKeystore = function() {
  // Alice credentials in the zeth abstraction
  const AliceOwnershipKeys = generateApkAskKeypair();
  const AliceEncKey = `-----BEGIN PUBLIC KEY-----
  MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDP34BAdxAX0p9yxhcoqkQtCKWc
  o/t/MEqLfjCP/dwkrN9MmML4CGYXqF0X9UKxv+2qxhtxkLLFtPnyT6PRTQDnPuHw
    +D8kQ4DOyn5fBVpIwvPVl/COIZYiSQgv2YaE8UI/9YtXLE9njJItsCJQbtcKY6TZ
  8JmIxk2E9fNah9V+SQIDAQAB
  -----END PUBLIC KEY-----`;
  const AliceDecKey = `-----BEGIN RSA PRIVATE KEY-----
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

  // Bob credentials in the zeth abstraction
  const BobOwnershipKeys = generateApkAskKeypair();
  const BobEncKey = `-----BEGIN PUBLIC KEY-----
  MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3Ba45mM+JhO9tNpHwldnnvAtA
    /j2XqiV4HNhkql39vt76oy6RV7Yl3KIW+dsT5EwZos8NmgvWo28pC4u+4nXbuNLH
  WVVt1jHQVhG9EQRlbkoCypDD4wOmrdlJplCjaRgCSeN8U7G+MTr2AtRT+0VozV04
  mIoKPDymx+pgH8KJVQIDAQAB
  -----END PUBLIC KEY-----`;
  const BobDecKey = `-----BEGIN RSA PRIVATE KEY-----
  MIICXAIBAAKBgQC3Ba45mM+JhO9tNpHwldnnvAtA/j2XqiV4HNhkql39vt76oy6R
  V7Yl3KIW+dsT5EwZos8NmgvWo28pC4u+4nXbuNLHWVVt1jHQVhG9EQRlbkoCypDD
  4wOmrdlJplCjaRgCSeN8U7G+MTr2AtRT+0VozV04mIoKPDymx+pgH8KJVQIDAQAB
  AoGBAJ7wNvHby3cgU5AjUK9+YuKEgb1qTHC2GJ3rZtxcuw0NwbQlG96qLgtJRBXx
  2xe2LYQhx++G9HrsKS+a0Dvvi+rQ7YK7cxFJuKNmwonoKI9LpIFDV7xvNJ1TPU1G
  QVskoU1OfwUabyDmYI5j7Lgf2xqu7Z2xNz1iQoMzFvI+ffItAkEA2GY+N3E3ZJWP
    +E6OuZHD08E0h9mPGoug5YQjhYEV0zyI9abGCzDZp90YKoLerTJefaD5NyErRVFn
  7jnFYGjxewJBANiDzSTMUeojGWboRhfHl/2FNSjg7ClgI8tjdH72Rn46EbLJHgno
  L3j5O1XwwgtbjTb/vRpc0V+gQp32qSlw728CQAhPnPIaKgt15wqdUcP0wjWexPq2
  s1VMqYhHE+ors//h4ky09AQ4AxP8XNI9Jno2ZgSjKw8f+f52iuxOUbNLNIMCQFfs
  vkQxTRqeAlTOApjpjwl/LOVa4cyzpBWWX9qnPF1KS6GlFrPDPHQOElCGIubl2OT6
  2dp40vXYaPUpE+0mVbUCQCxw7IvglwRKc142K7HfsSOdn0bQplS3ezEthriIzacP
  CCePPHuHI3A7+3ROFMKXmmjDauEMcpLhQen5f4/Corg=
    -----END RSA PRIVATE KEY-----`;

  // Charlie credentials in the zeth abstraction
  const CharlieOwnershipKeys = generateApkAskKeypair();
  const CharlieEncKey = `-----BEGIN RSA PRIVATE KEY-----
  MIICWwIBAAKBgQDz6F8PhRiHVCnfq5jxOx+N8Usov35NJSWQ3R/iRmNK+BeNedXb
  qvunEbLPEdus5h9BE2RwR0wumDe7WJWIjjRLEU7C5dJGDEviWlJBC+yw0wbnWA5F
  V6Mrq0UJSLVe5Q5uiLuHuzI9Ag9UOqJZTXQ5yfG89QRE8HumA1tzfxCrQwIDAQAB
  AoGATQ6v4bZZ7n9Pj2OmOShFqtF9vkzpeTPwL1k89n7oZcoFnuPMBc96G+lChZsN
  vQ0i+KtIwxQzZFEg4mZ1L6RFrofOyveFxsdI3LdpAbIKZujfatnsIjvjfYuZtV71
  63oP9HAbQnatrx3vhzZgw+FoIp/0M14J3wmHC/GpdLGxABkCQQD32fzy0lSzqVTp
  elxw7U+Rkze9WPcUEQYyaFDiB4COTudFwVTxoBZd2vxfbxpfr03no59shslZxzcl
  GWPs2gbnAkEA++0wy+H7DSTSQaDFsciVId6qAvNfM9wEUpq1WepvZTvOhyULp9PI
  TrxCtvYKPjKqU/7rPsJ8eVbBoAlhDJXZRQJAeu3imKkbm7R7ygWHffcmBOUIu2A5
  w/khorS8kS75Yxvdd2qJcAJftZNcoxTe9uBi+mXcN56ulVnKjxsFxb7ptwJAWixi
  RPgURnYhlEAZwzMKvl7W98tpDkT4fyDFPPP+/3tSx2jpLR9PGW+laZvTusOj2ADs
  7z/qEfyNvdzdkgWpCQJAZyTN+aWuoqhR9h3fsCLy4NisJ3z5reViXZVMKW4J8jat
  aKtIj2rMlUbT+hLkAQmUb4YZwxtPibPTIUFTwrHmiw==
    -----END RSA PRIVATE KEY-----`;
  const CharlieDecKey = `-----BEGIN PUBLIC KEY-----
  MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDz6F8PhRiHVCnfq5jxOx+N8Uso
  v35NJSWQ3R/iRmNK+BeNedXbqvunEbLPEdus5h9BE2RwR0wumDe7WJWIjjRLEU7C
  5dJGDEviWlJBC+yw0wbnWA5FV6Mrq0UJSLVe5Q5uiLuHuzI9Ag9UOqJZTXQ5yfG8
  9QRE8HumA1tzfxCrQwIDAQAB
  -----END PUBLIC KEY-----`;

  const keystore = {
    Alice: {
      AddrPk: {
        ek: AliceEncKey,
        a_pk: AliceOwnershipKeys.a_pk
      },
      AddrSk: {
        dk: AliceDecKey,
        a_sk: AliceOwnershipKeys.a_sk
      }
    },
    Bob: {
      AddrPk: {
        ek: BobEncKey,
        a_pk: BobOwnershipKeys.a_pk
      },
      AddrSk: {
        dk: BobDecKey,
        a_sk: BobOwnershipKeys.a_sk
      }
    },
    Charlie: {
      AddrPk: {
        ek: CharlieEncKey,
        a_pk: CharlieOwnershipKeys.a_pk
      },
      AddrSk: {
        dk: CharlieDecKey,
        a_sk: CharlieOwnershipKeys.a_sk
      }
    }
  };

  return keystore;
};

// Expose the module's functions
module.exports.noteRandomness = noteRandomness;
module.exports.createZethNote = createZethNote;
module.exports.hexFmt = hexFmt;
module.exports.computeCommitment = computeCommitment;
module.exports.computeNullifier = computeNullifier;
module.exports.decimalToHexadecimal = decimalToHexadecimal;
module.exports.deriveAPK = deriveAPK;
module.exports.generateApkAskKeypair = generateApkAskKeypair;
module.exports.createJSInput = createJSInput;
module.exports.parseHexadecimalPointBaseGroup1Affine = parseHexadecimalPointBaseGroup1Affine;
module.exports.parseHexadecimalPointBaseGroup2Affine = parseHexadecimalPointBaseGroup2Affine;
module.exports.initTestKeystore = initTestKeystore;
