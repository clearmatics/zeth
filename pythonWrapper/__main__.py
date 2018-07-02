import json
import web3

from web3 import Web3, HTTPProvider, TestRPCProvider
from web3.contract import ConciseContract

from solc import compile_files, link_code

from sender import deposit
from recipient import withdraw, generateProof, forward
from utils import hex2int, computeCommitment

w3 = Web3(HTTPProvider("http://localhost:8545"));

def compile():
    Miximus = "../contracts/Miximus.sol"
    MerkleTree = "../contracts/MerkleTree.sol"  
    Pairing =  "../contracts/Pairing.sol"
    Verifier = "../contracts/Verifier.sol"

    compiled_sol =  compile_files([Pairing, MerkleTree, Pairing, Verifier, Miximus], allow_paths="../contracts")
    miximus_interface = compiled_sol[Miximus + ':Miximus']
    verifier_interface = compiled_sol[Verifier + ':Verifier']
    return(miximus_interface, verifier_interface)
   
def deploy(path_to_vk):
    miximus_interface , verifier_interface  = compile()
    with open(path_to_vk) as json_data:
        vk = json.load(json_data)
    vk  = [
        hex2int(vk["a"][0]),
        hex2int(vk["a"][1]),
        hex2int(vk["b"]),
        hex2int(vk["c"][0]),
        hex2int(vk["c"][1]),
        hex2int(vk["g"][0]),
        hex2int(vk["g"][1]),
        hex2int(vk["gb1"]),
        hex2int(vk["gb2"][0]),
        hex2int(vk["gb2"][1]),
        hex2int(vk["z"][0]),
        hex2int(vk["z"][1]),
        hex2int(sum(vk["IC"], []))
    ]

    # Instantiate and deploy contract
    miximus = w3.eth.contract(abi=miximus_interface['abi'], bytecode=miximus_interface['bin'])
    verifier = w3.eth.contract(abi=verifier_interface['abi'], bytecode=verifier_interface['bin'])

    # Get transaction hash from deployed Verifier contract
    tx_hash = verifier.deploy(transaction={'from': w3.eth.accounts[0], 'gas': 4000000}, args=vk)

    # Get tx receipt to get Verifier contract address
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    verifier_address = tx_receipt['contractAddress']
    print("[INFO] Verifier address: ", verifier_address)

    # Deploy the Miximus contract once the Verifier is successfully deployed
    tx_hash = miximus.deploy(transaction={'from': w3.eth.accounts[0], 'gas': 4000000}, args=[verifier_address])

    # Get tx receipt to get Miximus contract address
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    miximus_address = tx_receipt['contractAddress']
    print("[INFO] Miximus address: ", miximus_address)

    # Contract instance in concise mode
    abi = miximus_interface['abi']
    miximus = w3.eth.contract(address=miximus_address, abi=abi, ContractFactoryClass=ConciseContract)

    return(miximus)

# Used for a debug purpose
def printBalances(sender, recipient1, recipient2, miximusContract):
    print("Sender balance --> ", w3.eth.getBalance(sender))
    print("Recipient1 balance --> ", w3.eth.getBalance(recipient1))
    print("Recipient2 balance --> ", w3.eth.getBalance(recipient2))
    print("Miximus cintract balance --> ", w3.eth.getBalance(miximusContract))

## MAIN
def main():
    senderAddress = w3.eth.accounts[0]
    recipient1Address = w3.eth.accounts[3]
    recipient2Address = w3.eth.accounts[5]
    tree_depth = 4; # Harcoded value for now

    path_to_vk = "../zksnark_element/vk.json"
    miximus_instance = deploy(path_to_vk)

    # -------------- DEPOSIT: Sender -> Recipient 1 --------------- #

    printBalances(senderAddress, recipient1Address, recipient2Address, miximus_instance.address)
    # Deposit to mixer
    resDeposit, nullifier, secret = deposit(miximus_instance, senderAddress, recipient1Address)

    # -------------- FORWARD: Recipient 1 --> Recipient 2 --------------- #

    printBalances(senderAddress, recipient1Address, recipient2Address, miximus_instance.address)
    # Generate proof to forward the payment
    unspentCommitment = '0x' + computeCommitment(nullifier, secret)
    tree = miximus_instance.getTree()
    generateProof(tree, tree_depth, 0, secret, nullifier, unspentCommitment) # Call the C++ cli prove command 
    # Forward payment
    txReceipt, newNullifier, newSecret = forward(miximus_instance, "./proof.json", recipient1Address, recipient2Address);

    # -------------- WITHDRAW: Recipient 1 --> Recipient 2 --------------- #

    printBalances(senderAddress, recipient1Address, recipient2Address, miximus_instance.address)
    # Generate proof to withdraw the funds
    newUnspentCommitment = '0x' + computeCommitment(newNullifier, newSecret)
    newTree = miximus_instance.getTree()
    generateProof(newTree, tree_depth, 1, newSecret, newNullifier, newUnspentCommitment) # Call the C++ cli prove command
    # Withdraw payment
    withdraw(miximus_instance, "./proof.json", recipient2Address)

    print(" ------ BALANCES at the end of the simulation ------ ")
    printBalances(senderAddress, recipient1Address, recipient2Address, miximus_instance.address)

if __name__== "__main__":
     main()
