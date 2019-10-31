import zethContracts
import zethMock
import zethConstants as constants
from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider

print("-------------------- Evaluating BaseMixer.sol --------------------")
w3 = Web3(HTTPProvider("http://localhost:8545"))
zksnark = "GROTH16"
# Zeth addresses
keystore = zethMock.initTestKeystore()
# Depth of the merkle tree (need to match the one used in the cpp prover)
mk_tree_depth = constants.ZETH_MERKLE_TREE_DEPTH
# Ethereum addresses
deployer_eth_address = w3.eth.accounts[0]
bob_eth_address = w3.eth.accounts[1]
alice_eth_address = w3.eth.accounts[2]
charlie_eth_address = w3.eth.accounts[3]

(proof_verifier_interface, otsig_verifier_interface, mixer_interface) = zethContracts.compile_contracts(zksnark)
hasher_interface, _ = zethContracts.compile_util_contracts()
(mixer_instance, initial_root) = zethContracts.deploy_contracts(
    mk_tree_depth,
    proof_verifier_interface,
    otsig_verifier_interface,
    mixer_interface,
    hasher_interface,
    deployer_eth_address,
    4000000,
    "0x0000000000000000000000000000000000000000", # We mix Ether in this test, so we set the addr of the ERC20 contract to be 0x0
    zksnark
)

# inputs represents a dummy primary input array
# inputs = rt || {sn}_1,2 || {cm}_1,2 || h_sig || {h}_1,2 || residual_bits
# residual_bits = v_in || v_out || h_sig || {sn}_1,2  || {cm}_1,2  || {h}_1,2
# v_in  = 0xFFFFFFFFFFFFFFFF
# v_out = 0x0000000000000000
# h_sig = 111
# sn_0  = 000
# sn_1  = 001
# cm_0  = 010
# cm_1  = 011
# h_0   = 100
# h_1   = 101
inputs = [0,1,1,2,2,3,4,4,713623846352979940490457358497079434602616037]
ok = True
start = 0
length = 3 # digest_length - field_capacity

for i in range(6):
    res = mixer_instance.functions.extract_extra_bits(start, length, inputs).call()
    ok = ( int.from_bytes(res, byteorder="big") == i )
    start += length
    assert ok == True
    "extract FAILS"

print("extract_extra_bits PASSES")