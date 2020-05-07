module.exports = function(cb) {
    var accountsA = web3.eth.getAccounts();
    accountsA.then(function(accounts) {
        var num_accounts = accounts.length;
        accounts.forEach(function (account) {
            var on_balance = function(balance) {
                console.log(account + ": " + balance);
                if (--num_accounts == 0) {
                    cb();
                }
            };
            web3.eth.getBalance(account).then(on_balance);
        });
    });
}
