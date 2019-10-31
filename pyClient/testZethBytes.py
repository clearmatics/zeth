import os
from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider
from solcx import compile_standard, compile_files

print("-------------------- Evaluating Bytes.sol --------------------")
w3 = Web3(HTTPProvider("http://localhost:8545"))
contracts_dir = os.environ['ZETH_CONTRACTS_DIR']
path_to_bytes = os.path.join(contracts_dir, "Bytes.sol")
path_to_bytes_tests = os.path.join(contracts_dir, "Bytes_tests.sol")
compiled_sol = compile_files([path_to_bytes, path_to_bytes_tests])
bytes_interface = compiled_sol[path_to_bytes_tests + ':' + "Bytes_tests"]
contract = w3.eth.contract(abi=bytes_interface['abi'], bytecode=bytes_interface['bin'])
tx_hash = contract.constructor().transact({'from':w3.eth.accounts[1]})
tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 100000)
address = tx_receipt['contractAddress']
bytes_instance = w3.eth.contract(
    address=address,
    abi=bytes_interface['abi']
)


print("--- testing ", "testReverseByte")
assert bytes_instance.functions.testReverseByte().call() == True
"testReverseByte FAILS"

print("--- testing ", "testGetLastByte")
assert bytes_instance.functions.testGetLastByte().call() == True
"testGetLastByte FAILS"

print("--- testing ", "testFlipEndiannessBytes32")
assert bytes_instance.functions.testFlipEndiannessBytes32().call() == True
"testFlipEndiannessBytes32 FAILS"

print("--- testing ", "testBytesToBytes32")
assert bytes_instance.functions.testBytesToBytes32().call() == True
"testBytesToBytes32 FAILS"

print("--- testing ", "testSha256DigestFromFieldElements")
assert bytes_instance.functions.testSha256DigestFromFieldElements().call() == True
"testSha256DigestFromFieldElements FAILS"

print("--- testing ", "testSwapBitOrder")
assert bytes_instance.functions.testSwapBitOrder().call() == True
"testSwapBitOrder FAILS"

print("all Bytes tests PASS")