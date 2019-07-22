import json
import time
import os
import sys

from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider

import numpy as np
import os
import signal
import subprocess

# Get the utils to deploy and call the contracts
import zethContracts
# Get the utils written to interact with the prover
import zethGRPC
# Get the mock data for the test
import zethMock
# Get the zeth utils functions
import zethUtils
# Get the test scenario
import zethTestScenario as zethTest
# Get the zeth constants
import zethConstants as constants

w3 = Web3(HTTPProvider(constants.WEB3_HTTP_PROVIDER))
test_grpc_endpoint = constants.RPC_ENDPOINT


nb_tests = 10

# Call to the mixer's mix function to do zero knowledge payments
def mix_pghr13(
        mixer_instance,
        ciphertext1,
        ciphertext2,
        parsed_proof,
        sender_address,
        wei_pub_value,
        call_gas
    ):
    mix_time_start = time.time()
    tx_hash = mixer_instance.functions.mix(
        ciphertext1,
        ciphertext2,
        zethGRPC.hex2int(parsed_proof["a"]),
        zethGRPC.hex2int(parsed_proof["a_p"]),
        [zethGRPC.hex2int(parsed_proof["b"][0]), zethGRPC.hex2int(parsed_proof["b"][1])],
        zethGRPC.hex2int(parsed_proof["b_p"]),
        zethGRPC.hex2int(parsed_proof["c"]),
        zethGRPC.hex2int(parsed_proof["c_p"]),
        zethGRPC.hex2int(parsed_proof["h"]),
        zethGRPC.hex2int(parsed_proof["k"]),
        zethGRPC.hex2int(parsed_proof["inputs"])
    ).transact({'from': sender_address, 'value': wei_pub_value, 'gas': call_gas})
    mix_time_end= time.time()

    trans_time_start = time.time()
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    trans_time_end = time.time()

    return zethContracts.parse_mix_call(mixer_instance, tx_receipt), tx_receipt.gasUsed, mix_time_end - mix_time_start, trans_time_end - trans_time_start

def mix_groth16(
        mixer_instance,
        ciphertext1,
        ciphertext2,
        parsed_proof,
        sender_address,
        wei_pub_value,
        call_gas
    ):
    mix_time_start = time.time()
    tx_hash = mixer_instance.functions.mix(
        ciphertext1,
        ciphertext2,
        zethGRPC.hex2int(parsed_proof["a"]),
        [zethGRPC.hex2int(parsed_proof["b"][0]), zethGRPC.hex2int(parsed_proof["b"][1])],
        zethGRPC.hex2int(parsed_proof["c"]),
        zethGRPC.hex2int(parsed_proof["inputs"])
    ).transact({'from': sender_address, 'value': wei_pub_value, 'gas': call_gas})
    mix_time_end= time.time()

    trans_time_start = time.time()
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    trans_time_end = time.time()

    return zethContracts.parse_mix_call(mixer_instance, tx_receipt), tx_receipt.gasUsed, mix_time_end - mix_time_start, trans_time_end - trans_time_start

def mix(
        mixer_instance,
        ciphertext1,
        ciphertext2,
        parsed_proof,
        sender_address,
        wei_pub_value,
        call_gas,
        zksnark
    ):
    if zksnark == constants.PGHR13_ZKSNARK:
        return mix_pghr13(
            mixer_instance,
            ciphertext1,
            ciphertext2,
            parsed_proof,
            sender_address,
            wei_pub_value,
            call_gas
        )
    elif zksnark == constants.GROTH16_ZKSNARK:
        return mix_groth16(
            mixer_instance,
            ciphertext1,
            ciphertext2,
            parsed_proof,
            sender_address,
            wei_pub_value,
            call_gas
        )
    else:
        return sys.exit(errors.SNARK_NOT_SUPPORTED)


zero_wei_hex = "0000000000000000"


if __name__ == '__main__':
    zksnark = zethUtils.parse_zksnark_arg()


    proof_dts = np.array([])
    mix_dts = np.array([])
    tx_dts = np.array([])
    tot_dts = np.array([])
    gas_array = np.array([])

    p = subprocess.Popen("ps -aux | grep 'ganache-cli' | grep -v grep", shell = True, stdout=subprocess.PIPE)
    processes = p.communicate()
    if type(processes) == tuple:
        for pi in processes:
            if type(pi) == str:
                if len(pi.split())>2:
                    pid = int(pi.split()[1])
                    os.kill(pid, signal.SIGUSR1)
    try:
        os.kill(int(p.pid), signal.SIGUSR1)
    except Exception as e:
        print()


    print("[INFO] Running Deposit benchmark")
    before_test = time.time()
    for nbtest in range(nb_tests):
        current_time = time.time()
        print("------------------------------ Test number "+str(nbtest+1)+"/"+str(nb_tests), "time since beginning: "+str(current_time-before_test))

        p = subprocess.Popen("ganache-cli -e", shell = True, stdout=subprocess.PIPE)
        
        # Zeth addresses
        keystore = zethMock.initTestKeystore()
        # Depth of the merkle tree (need to match the one used in the cpp prover)
        mk_tree_depth = constants.ZETH_MERKLE_TREE_DEPTH
        # Ethereum addresses
        deployer_eth_address = w3.eth.accounts[0]
        bob_eth_address = w3.eth.accounts[1]
        alice_eth_address = w3.eth.accounts[2]
        charlie_eth_address = w3.eth.accounts[3]

        vk = zethGRPC.getVerificationKey(test_grpc_endpoint)

        zethGRPC.writeVerificationKey(vk, zksnark)

        (verifier_interface, mixer_interface) = zethContracts.compile_contracts(zksnark)
        hasher_interface, _ = zethContracts.compile_util_contracts()
        (mixer_instance, initial_root) = zethContracts.deploy_contracts(
            mk_tree_depth,
            verifier_interface,
            mixer_interface,
            hasher_interface,
            deployer_eth_address,
            4000000,
            "0x0000000000000000000000000000000000000000", # We mix Ether in this test, so we set the addr of the ERC20 contract to be 0x0
            zksnark
        )

        bob_apk = keystore["Bob"]["AddrPk"]["aPK"]
        bob_ask = keystore["Bob"]["AddrSk"]["aSK"]



        for leaf in range(2**(constants.ZETH_MERKLE_TREE_DEPTH-1)):
            try:
                test_time_start = time.time()
                (input_note1, input_nullifier1, input_address1) = zethMock.getDummyInput(bob_apk, bob_ask)
                (input_note2, input_nullifier2, input_address2) = zethMock.getDummyInput(bob_apk, bob_ask)
                dummy_mk_path = zethMock.getDummyMerklePath(mk_tree_depth)

                input_nullifier1 = zethGRPC.computeNullifier(input_note1, bob_ask)
                input_nullifier2 = zethGRPC.computeNullifier(input_note2, bob_ask)
                js_inputs = [
                    zethGRPC.createJSInput(dummy_mk_path, input_address1, input_note1, bob_ask, input_nullifier1),
                    zethGRPC.createJSInput(dummy_mk_path, input_address2, input_note2, bob_ask, input_nullifier2)
                ]

                output_note1 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), bob_apk, zethGRPC.int64ToHexadecimal(Web3.toWei('2', 'ether')))
                output_note2 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), bob_apk, zethGRPC.int64ToHexadecimal(Web3.toWei('2', 'ether')))
                js_outputs = [
                    output_note1,
                    output_note2
                ]

                proof_input = zethGRPC.makeProofInputs(initial_root, js_inputs, js_outputs, zethGRPC.int64ToHexadecimal(Web3.toWei('4', 'ether')), zero_wei_hex)

                proof_time_start = time.time()
                proof_obj = zethGRPC.getProof(test_grpc_endpoint, proof_input)
                proot_time_end = time.time()
                proof_duration = proot_time_end - proof_time_start

                proof_json = zethGRPC.parseProof(proof_obj, zksnark)

                output_note1_str = json.dumps(zethGRPC.parseZethNote(output_note1))
                output_note2_str = json.dumps(zethGRPC.parseZethNote(output_note2))

                ciphertext1 = zethUtils.encrypt(output_note1_str, keystore["Bob"]["AddrPk"]["ek"])
                ciphertext2 = zethUtils.encrypt(output_note2_str, keystore["Bob"]["AddrPk"]["ek"])

                result_deposit_bob_to_bob, gas_cost, mix_duration, trans_duration =  mix(
                    mixer_instance,
                    ciphertext1,
                    ciphertext2,
                    proof_json,
                    bob_eth_address,
                    w3.toWei(4, 'ether'),
                    4000000,
                    zksnark
                )
                test_time_end = time.time()
                tot_duration = proof_duration+ mix_duration+ trans_duration

                proof_dts = np.append(proof_dts, [proof_duration])
                mix_dts = np.append(mix_dts, [mix_duration])
                tx_dts = np.append(tx_dts, [trans_duration])
                tot_dts = np.append(tot_dts, [tot_duration])
                gas_array = np.append(gas_array, [int(gas_cost)])
            except Exception as e:
                print(e)

            os.kill(int(p.pid), signal.SIGUSR1)

    after_test = time.time()
    print("Test total time", after_test - before_test )

    print("-------------- Average: ")
    print("Dt_gen_proof: "+str(np.mean(proof_dts)))
    print("Dt_mix: " + str(np.mean(mix_dts)))
    print("Dt_tx: " + str(np.mean(tx_dts)))
    print("Dt_tot: " + str(np.mean(tot_dts)))
    print("gas_cost:" + str(np.mean(gas_array)))

    print("\n-------------- Variance: ")
    print("Var: ", "Dt_gen_proof: " + str(np.var(proof_dts)))
    print("Dt_mix: " + str(np.var(mix_dts)))
    print("Dt_tx: " + str(np.var(tx_dts)))
    print("Dt_tot: " + str(np.var(tot_dts)))
    print("gas_cost: " + str(np.var(gas_array)))
