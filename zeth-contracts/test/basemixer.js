const BaseMixer_tests = artifacts.require("./BaseMixer_tests.sol");

const testContracts = {
    BaseMixer_tests: BaseMixer_tests
};

const allSimpleTests = {
    BaseMixer_tests:  [
    "test_extract_extra_bits"
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
