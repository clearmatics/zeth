# Benchmarking Gas cost for different MiMC exponents
import zethContracts
import math

from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider
w3 = Web3(HTTPProvider("http://localhost:8545"))

# compile MiMC, MerkleeTree contracts
mimc_interface, tree_interface = zethContracts.compile_util_contracts()

# deploy MimC contract
mimc_instance, mimc_address = zethContracts.deploy_mimc_contract(mimc_interface)

# deploy MerkleTreeMiMCHash contract
tree_instance = zethContracts.deploy_tree_contract(tree_interface, 3, mimc_address)


# Harry code test vector:  https://github.com/HarryR/ethsnarks/blob/master/src/test/test_mimc_hash.cpp
m1 = 3703141493535563179657531719960160174296085208671919316200479060314459804651
m2 = 134551314051432487569247388144051420116740427803855572138106146683954151557
iv = 918403109389145570117360101535982733651217667914747213867238065296420114726
out = 15683951496311901749339509118960676303290224812129752890706581988986633412003

# Test cases generated from https://github.com/riemann89/ethsnarks/blob/master/src/utils/mimc_hash_test_cases.cpp
root = 10734222616343366978183290578250016397752183448862818550078506087190022377626
level_1 = 4571162561214823491685468001824923339916598569432941893158208026396444541263
level_2 = 21783731659988531455046720456618223572462885645210824868284396990406188448077

if __name__ == "__main__":
  # MiMC contract unit test
  hash = zethContracts.mimcHash(mimc_instance,
  [m1.to_bytes(32, byteorder="big"), m2.to_bytes(32, byteorder="big")], iv.to_bytes(32, byteorder="big"))

  assert int.from_bytes(hash, byteorder="big") == out
  "Hash is NOT correct"

  # MerkleTreeMiMCHash of depth 3 unit test
  tree = zethContracts.getTree(tree_instance)
  for i in range(7,15):
    assert int.from_bytes(tree[i], byteorder="big") == 0
    "MerkleTree Error"

  for i in range(3, 7):
    assert int.from_bytes(tree[i], byteorder="big") == level_2

  for i in range(1, 3):
    assert int.from_bytes(tree[i], byteorder="big") == level_1

  assert int.from_bytes(tree[0], byteorder="big") == root
