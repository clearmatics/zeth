module.exports = {
  networks: {
    development: {
      host: "localhost",
      port: 8545,
      gas: 0x3FFFFFFFFFFFF,
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
    autonityhelloworld: {
        host: "localhost",
        port: 8541,
        network_id: "*",
    },
  },
  mocha: {
    useColors: true,
    enableTimeouts: false
  },
  compilers: {
    solc: {
      version: "^0.8.0",
      settings: {
        optimizer: {
          enabled: true,
          runs: 200
        }
      }
    }
  }
};
