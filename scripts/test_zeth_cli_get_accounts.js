module.exports = function(cb) {
    var accountsA = web3.eth.getAccounts();
    accountsA.then(function(accounts) {
        console.log("deployer: " + accounts[0]);
        console.log("alice: " + accounts[1]);
        console.log("bob: " + accounts[2]);
        console.log("charlie: " + accounts[3]);
        cb();
    });
    // var accounts = await accountsA;
    // console.log(accounts);
}
