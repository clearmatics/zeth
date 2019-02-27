module.exports = {
  networks: {
    development: {
      host: "localhost",
      port: 8545,
      gas: 0xFFFFFFFFFFF,
      gasprice: 0x1,
      network_id: "*"
    },
    coverage: {
      host: "localhost",
      port: 8555,
      gas: 0xFFFFFFF,
      gasprice: 0x1,
      network_id: "*" // Match any network id
    },
  },
  mocha: {
    useColors: true,
    enableTimeouts: false
  },
  solc: {
    optimizer: {
      enabled: true,
        runs: 200
    }
  }
};
