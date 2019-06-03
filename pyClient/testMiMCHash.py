# Benchmarking Gas cost for different MiMC exponents
import zethContracts
import math

from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider
w3 = Web3(HTTPProvider("http://localhost:8545"))

# compile/deploy contracts
mimc_interface = zethContracts.compile_util_contracts()
mimc_instance = zethContracts.deploy_mimc(mimc_interface)

# Harry code test vector:  https://github.com/HarryR/ethsnarks/blob/master/src/test/test_mimc_hash.cpp
m1 = 3703141493535563179657531719960160174296085208671919316200479060314459804651
m2 = 134551314051432487569247388144051420116740427803855572138106146683954151557
iv = 918403109389145570117360101535982733651217667914747213867238065296420114726
out = 15683951496311901749339509118960676303290224812129752890706581988986633412003

hash = zethContracts.mimcHash(mimc_instance,
  [m1.to_bytes(32, byteorder="big"), m2.to_bytes(32, byteorder="big")], iv.to_bytes(32, byteorder="big"))

assert int.from_bytes(hash, byteorder="big") == out
"Hash is NOT correct"
