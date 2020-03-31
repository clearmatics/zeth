module.exports = function(cb) {
    newAccountA = web3.eth.personal.newAccount();
    newAccountA.then(function (account) {
        console.log(account);
        cb();
    });
};
