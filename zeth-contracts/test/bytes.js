const Bytes_tests = artifacts.require("./Bytes_tests.sol");

const testContracts = {
  Bytes_tests: Bytes_tests
};

const allSimpleTests = {
  Bytes_tests:  [
    "testReverseByte",
    "testGetLastByte",
    "testFlipEndiannessBytes32",
    "testBytesToBytes32",
    "testSha256DigestFromFieldElements"
  ]
};

Object.keys(allSimpleTests).forEach(function(k) {
  var obj = testContracts[k];
  contract(k, (accounts) => {
    allSimpleTests[k].forEach(function (name) {
      it(name, (done) => {
        obj.deployed().then((instance) => {
          const txObj = {from: accounts[0]};
          instance[name].call(txObj).then(result => {
            assert.ok(result, k + "." + name + " [Test Fail] Boolean value expected true");
            done();
          });
        });
      });
    });
  });
});
