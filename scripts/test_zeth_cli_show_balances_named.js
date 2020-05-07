module.exports = function(cb) {
    var accountsA = web3.eth.getAccounts();
    accountsA.then(function(accounts) {
        var shown = 0;
        var on_balance = function(name) {
            return function(bal) {
                console.log(name + ": " + bal);
                if (++shown == 4) { cb(); }
            };
        };

        web3.eth.getBalance(accounts[0]).then(on_balance("deployer "));
        web3.eth.getBalance(accounts[1]).then(on_balance("alice    "));
        web3.eth.getBalance(accounts[2]).then(on_balance("bob      "));
        web3.eth.getBalance(accounts[3]).then(on_balance("charlie  "));
    });
}
