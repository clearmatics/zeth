import web3

from web3 import Web3, HTTPProvider
from utils import generateNullifier, generateSecret, computeCommitment

w3 = Web3(HTTPProvider("http://localhost:8545"));

def deposit_call(miximus, nullifier, sk, depositAddress):
    commitment = '0x' + computeCommitment(nullifier, sk)
    print("[DEBUG] leaf/commitment: ", commitment)
    print("[DEBUG] nullifier: ", nullifier)
    print("[DEBUG] sk: ", sk)

    tx_hash = miximus.deposit(commitment, transact={'from': depositAddress, 'gas': 4000000, "value": w3.toWei(1, "ether")})
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    return tx_receipt

def deposit(miximus, senderAddress, recipientAddress):
    nullifier = generateNullifier(recipientAddress)
    secret = generateSecret()
    resDeposit = deposit_call(miximus, nullifier, secret, senderAddress)
    return(resDeposit, nullifier, secret)
