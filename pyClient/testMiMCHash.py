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

# Test cases generated from https://github.com/riemann89/ethsnarks/blob/master/src/utils/mimc_hash_test_cases.cpp with mt_iv
root = 11716064043359892586827861099037056012854304663991858447116188660975533174593
level_1 = 8830982470254157157072290926830971455574680711064480284113552856555397977780
level_2 = 2689880186515302973494776427415865270938416831401566119966263629471944181012


if __name__ == "__main__":
  # MiMC contract unit test
  hash = zethContracts.mimcHash(mimc_instance,
  [m1.to_bytes(32, byteorder="big"), m2.to_bytes(32, byteorder="big")], iv.to_bytes(32, byteorder="big"))

  assert int.from_bytes(hash, byteorder="big") == out
  "Hash is NOT correct"

  # MerkleTreeMiMCHash of depth 3 unit test
  tree = zethContracts.getTree(tree_instance)
  root_recovered = zethContracts.getRoot(tree_instance)
  for i in range(7,15):
    assert int.from_bytes(tree[i], byteorder="big") == 0
    "MerkleTree Error"

  for i in range(3, 7):
    print("LEVEL 2:"+str(int.from_bytes(tree[i], byteorder="big")))
    print(i)
    assert int.from_bytes(tree[i], byteorder="big") == level_2

  for i in range(1, 3):
    print("LEVEL 1:"+str(int.from_bytes(tree[i], byteorder="big")))
    assert int.from_bytes(tree[i], byteorder="big") == level_1

  print("ROOT:"+str(int.from_bytes(tree[0], byteorder="big")))
  assert int.from_bytes(tree[0], byteorder="big") == root

  print("ROOT RECOVERED:"+str(int.from_bytes(root_recovered, byteorder="big")))
  assert int.from_bytes(root_recovered, byteorder="big") == root
