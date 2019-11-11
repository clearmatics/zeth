import zeth.constants as constants
import zeth.errors as errors
from zeth.utils import get_trusted_setup_dir, get_contracts_dir, hex_to_int
from zeth.joinsplit import GenericVerificationKey, GenericProof, \
    JoinsplitPublicKey

import json
import os
import sys
from web3 import Web3, HTTPProvider  # type: ignore
from solcx import compile_files  # type: ignore
from typing import Tuple, Dict, List, Any

W3 = Web3(HTTPProvider(constants.WEB3_HTTP_PROVIDER))
# pylint is not aware of W3.eth. This prevents it from complaining.
eth = W3.eth  # pylint: disable=no-member, invalid-name

Interface = Dict[str, Any]


class MixResult:
    """
    Data structure representing the result of the mix call.
    """
    def __init__(
            self,
            cm_address_1: int,
            cm_address_2: int,
            new_merkle_root: str,
            pk_sender: bytes,
            ciphertext_1: bytes,
            ciphertext_2: bytes):
        self.cm_address_1 = cm_address_1
        self.cm_address_2 = cm_address_2
        self.new_merkle_root = new_merkle_root
        self.pk_sender = pk_sender
        self.ciphertext_1 = ciphertext_1
        self.ciphertext_2 = ciphertext_2


def get_zksnark_files(zksnark: str) -> Tuple[str, str]:
    """
    Returns the files to use for the given zkSNARK (verifier_contract,
    mixer_contract)
    """
    if zksnark == constants.PGHR13_ZKSNARK:
        return (
            constants.PGHR13_VERIFIER_CONTRACT, constants.PGHR13_MIXER_CONTRACT)
    if zksnark == constants.GROTH16_ZKSNARK:
        return (
            constants.GROTH16_VERIFIER_CONTRACT, constants.GROTH16_MIXER_CONTRACT)
    return sys.exit(errors.SNARK_NOT_SUPPORTED)


def compile_contracts(zksnark: str) -> Tuple[Interface, Interface, Interface]:
    contracts_dir = get_contracts_dir()
    (proof_verifier_name, mixer_name) = get_zksnark_files(zksnark)
    otsig_verifier_name = constants.SCHNORR_VERIFIER_CONTRACT

    path_to_proof_verifier = os.path.join(
        contracts_dir, proof_verifier_name + ".sol")
    path_to_otsig_verifier = os.path.join(
        contracts_dir, otsig_verifier_name + ".sol")
    path_to_mixer = os.path.join(contracts_dir, mixer_name + ".sol")

    compiled_sol = compile_files(
        [path_to_proof_verifier, path_to_otsig_verifier, path_to_mixer])

    proof_verifier_interface = \
        compiled_sol[path_to_proof_verifier + ':' + proof_verifier_name]
    otsig_verifier_interface = \
        compiled_sol[path_to_otsig_verifier + ':' + otsig_verifier_name]
    mixer_interface = compiled_sol[path_to_mixer + ':' + mixer_name]

    return (proof_verifier_interface, otsig_verifier_interface, mixer_interface)


def compile_util_contracts() -> Tuple[Interface, Interface]:
    contracts_dir = get_contracts_dir()
    path_to_pairing = os.path.join(contracts_dir, "Pairing.sol")
    path_to_bytes = os.path.join(contracts_dir, "Bytes.sol")
    path_to_mimc7 = os.path.join(contracts_dir, "MiMC7.sol")
    path_to_tree = os.path.join(contracts_dir, "MerkleTreeMiMC7.sol")
    compiled_sol = compile_files(
        [path_to_pairing, path_to_bytes, path_to_mimc7, path_to_tree])
    mimc_interface = compiled_sol[path_to_mimc7 + ':' + "MiMC7"]
    tree_interface = compiled_sol[path_to_tree + ':' + "MerkleTreeMiMC7"]
    return mimc_interface, tree_interface


def deploy_pghr13_verifier(
        vk: Dict[str, Any],
        verifier: Any,
        deployer_address: str,
        deployment_gas: int) -> str:
    """
    Deploy the verifier used with PGHR13
    """
    # Deploy the verifier contract with the good verification key
    tx_hash = verifier.constructor(
        A1=hex_to_int(vk["a"][0]),
        A2=hex_to_int(vk["a"][1]),
        B=hex_to_int(vk["b"]),
        C1=hex_to_int(vk["c"][0]),
        C2=hex_to_int(vk["c"][1]),
        gamma1=hex_to_int(vk["g"][0]),
        gamma2=hex_to_int(vk["g"][1]),
        gammaBeta1=hex_to_int(vk["gb1"]),
        gammaBeta2_1=hex_to_int(vk["gb2"][0]),
        gammaBeta2_2=hex_to_int(vk["gb2"][1]),
        Z1=hex_to_int(vk["z"][0]),
        Z2=hex_to_int(vk["z"][1]),
        IC_coefficients=hex_to_int(sum(vk["IC"], []))
    ).transact({'from': deployer_address, 'gas': deployment_gas})

    # Get tx receipt to get Verifier contract address
    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 10000)
    verifier_address = tx_receipt['contractAddress']
    return verifier_address


def deploy_mixer(
        proof_verifier_address: str,
        otsig_verifier_address: str,
        mixer_interface: Interface,
        mk_tree_depth: int,
        deployer_address: str,
        deployment_gas: int,
        token_address: str,
        hasher_address: str) -> Tuple[Any, str]:
    """
    Common function to deploy a mixer contract. Returns the mixer and the
    initial merkle root of the commitment tree
    """
    # Deploy the Mixer contract once the Verifier is successfully deployed
    mixer = eth.contract(
        abi=mixer_interface['abi'], bytecode=mixer_interface['bin'])

    tx_hash = mixer.constructor(
        snark_ver=proof_verifier_address,
        sig_ver=otsig_verifier_address,
        mk_depth=mk_tree_depth,
        token=token_address,
        hasher=hasher_address
    ).transact({'from': deployer_address, 'gas': deployment_gas})
    # Get tx receipt to get Mixer contract address
    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 10000)
    mixer_address = tx_receipt['contractAddress']
    # Get the mixer contract instance
    mixer = eth.contract(
        address=mixer_address,
        abi=mixer_interface['abi']
    )
    # Get the initial merkle root to proceed to the first payments
    ef_log_merkle_root = \
        mixer.eventFilter("LogMerkleRoot", {'fromBlock': 'latest'})
    event_logs_log_merkle_root = ef_log_merkle_root.get_all_entries()
    initial_root = W3.toHex(event_logs_log_merkle_root[0].args.root)
    return(mixer, initial_root[2:])


def deploy_groth16_verifier(
        vk: GenericVerificationKey,
        verifier: Any,
        deployer_address: str,
        deployment_gas: int) -> str:
    """
    Deploy the verifier and the mixer used with GROTH16
    """
    # Deploy the verifier contract with the good verification key
    tx_hash = verifier.constructor(
        Alpha=hex_to_int(vk["alpha_g1"]),
        Beta1=hex_to_int(vk["beta_g2"][0]),
        Beta2=hex_to_int(vk["beta_g2"][1]),
        Delta1=hex_to_int(vk["delta_g2"][0]),
        Delta2=hex_to_int(vk["delta_g2"][1]),
        ABC_coords=hex_to_int(sum(vk["abc_g1"], []))
    ).transact({'from': deployer_address, 'gas': deployment_gas})

    # Get tx receipt to get Verifier contract address
    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 10000)
    verifier_address = tx_receipt['contractAddress']
    return verifier_address


def deploy_otschnorr_contracts(
        verifier: Any,
        deployer_address: str,
        deployment_gas: int) -> str:
    """
    Deploy the verifier used with OTSCHNORR
    """
    # Deploy the verifier contract with the good verification key
    tx_hash = verifier.constructor().transact(
            {'from': deployer_address, 'gas': deployment_gas})

    # Get tx receipt to get Verifier contract address
    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 10000)
    verifier_address = tx_receipt['contractAddress']
    return verifier_address


def deploy_contracts(
        mk_tree_depth: int,
        proof_verifier_interface: Interface,
        otsig_verifier_interface: Interface,
        mixer_interface: Interface,
        hasher_interface: Interface,
        deployer_address: str,
        deployment_gas: int,
        token_address: str,
        zksnark: str) -> Tuple[Any, str]:
    """
    Deploy the mixer contract with the given merkle tree depth and returns an
    instance of the mixer along with the initial merkle tree root to use for
    the first zero knowledge payments
    """
    setup_dir = get_trusted_setup_dir()
    vk_json = os.path.join(setup_dir, "vk.json")
    with open(vk_json) as json_data:
        vk = json.load(json_data)

    # Deploy the proof verifier contract with the good verification key
    proof_verifier = eth.contract(
        abi=proof_verifier_interface['abi'],
        bytecode=proof_verifier_interface['bin']
    )
    proof_verifier_address = ""
    if zksnark == constants.PGHR13_ZKSNARK:
        proof_verifier_address = deploy_pghr13_verifier(
            vk, proof_verifier, deployer_address, deployment_gas)
    elif zksnark == constants.GROTH16_ZKSNARK:
        proof_verifier_address = deploy_groth16_verifier(
                vk, proof_verifier, deployer_address, deployment_gas)
    else:
        return sys.exit(errors.SNARK_NOT_SUPPORTED)

    # Deploy MiMC contract
    _, hasher_address = deploy_mimc_contract(hasher_interface)  # type: ignore

    # Deploy the one-time signature verifier contract
    otsig_verifier = eth.contract(
        abi=otsig_verifier_interface['abi'],
        bytecode=otsig_verifier_interface['bin'])
    otsig_verifier_address = deploy_otschnorr_contracts(
            otsig_verifier, deployer_address, deployment_gas)

    return deploy_mixer(
            proof_verifier_address,
            otsig_verifier_address,
            mixer_interface,
            mk_tree_depth,
            deployer_address,
            deployment_gas,
            token_address,
            hasher_address)


def deploy_mimc_contract(interface: Interface) -> Tuple[Any, str]:
    """
    Deploy mimc contract
    """
    contract = eth.contract(abi=interface['abi'], bytecode=interface['bin'])
    tx_hash = contract.constructor().transact({'from': eth.accounts[1]})
    # Get tx receipt to get Mixer contract address
    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 10000)
    address = tx_receipt['contractAddress']
    # Get the mixer contract instance
    instance = eth.contract(
        address=address,
        abi=interface['abi']
    )
    return instance, address


def deploy_tree_contract(
        interface: Interface,
        depth: int,
        hasher_address: str) -> Any:
    """
    Deploy tree contract
    """
    contract = eth.contract(abi=interface['abi'], bytecode=interface['bin'])
    tx_hash = contract \
        .constructor(hasher_address, depth) \
        .transact({'from': eth.accounts[1]})
    # Get tx receipt to get Mixer contract address
    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 10000)
    address = tx_receipt['contractAddress']
    # Get the mixer contract instance
    instance = eth.contract(
        address=address,
        abi=interface['abi']
    )
    return instance


def mix_pghr13(
        mixer_instance: Any,
        pk_sender: bytes,
        ciphertext1: bytes,
        ciphertext2: bytes,
        parsed_proof: GenericProof,
        vk: JoinsplitPublicKey,
        sigma: int,
        sender_address: str,
        wei_pub_value: int,
        call_gas: int) -> MixResult:
    """
    Call to the mixer's mix function to do zero knowledge payments
    """
    tx_hash = mixer_instance.functions.mix(
        hex_to_int(parsed_proof["a"]),
        hex_to_int(parsed_proof["a_p"]),
        [hex_to_int(parsed_proof["b"][0]),
         hex_to_int(parsed_proof["b"][1])],
        hex_to_int(parsed_proof["b_p"]),
        hex_to_int(parsed_proof["c"]),
        hex_to_int(parsed_proof["c_p"]),
        hex_to_int(parsed_proof["h"]),
        hex_to_int(parsed_proof["k"]),
        [[int(vk[0][0]), int(vk[0][1])], [int(vk[1][0]), int(vk[1][1])]],
        int(sigma),
        hex_to_int(parsed_proof["inputs"]),
        pk_sender,
        ciphertext1,
        ciphertext2,
    ).transact({'from': sender_address, 'value': wei_pub_value, 'gas': call_gas})

    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 10000)
    return parse_mix_call(mixer_instance, tx_receipt)


def mix_groth16(
        mixer_instance: Any,
        pk_sender: bytes,
        ciphertext1: bytes,
        ciphertext2: bytes,
        parsed_proof: GenericProof,
        vk: JoinsplitPublicKey,
        sigma: int,
        sender_address: str,
        wei_pub_value: int,
        call_gas: int) -> MixResult:
    tx_hash = mixer_instance.functions.mix(
        hex_to_int(parsed_proof["a"]),
        [hex_to_int(parsed_proof["b"][0]),
         hex_to_int(parsed_proof["b"][1])],
        hex_to_int(parsed_proof["c"]),
        [[int(vk[0][0]), int(vk[0][1])], [int(vk[1][0]), int(vk[1][1])]],
        int(sigma),
        hex_to_int(parsed_proof["inputs"]),
        pk_sender,
        ciphertext1,
        ciphertext2,
    ).transact({'from': sender_address, 'value': wei_pub_value, 'gas': call_gas})

    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 10000)
    return parse_mix_call(mixer_instance, tx_receipt)


def mix(
        mixer_instance: Any,
        pk_sender: bytes,
        ciphertext1: bytes,
        ciphertext2: bytes,
        parsed_proof: GenericProof,
        vk: JoinsplitPublicKey,
        sigma: int,
        sender_address: str,
        wei_pub_value: int,
        call_gas: int,
        zksnark: str) -> MixResult:
    if zksnark == constants.PGHR13_ZKSNARK:
        return mix_pghr13(
            mixer_instance,
            pk_sender,
            ciphertext1,
            ciphertext2,
            parsed_proof,
            vk,
            sigma,
            sender_address,
            wei_pub_value,
            call_gas
        )
    if zksnark == constants.GROTH16_ZKSNARK:
        return mix_groth16(
            mixer_instance,
            pk_sender,
            ciphertext1,
            ciphertext2,
            parsed_proof,
            vk,
            sigma,
            sender_address,
            wei_pub_value,
            call_gas
        )
    return sys.exit(errors.SNARK_NOT_SUPPORTED)


def parse_mix_call(
        mixer_instance: Any,
        _tx_receipt: str) -> MixResult:
    """
    Get the logs data associated with this mixing
    """
    # Gather the addresses of the appended commitments
    event_filter_log_address = mixer_instance.eventFilter(
        "LogAddress",
        {'fromBlock': 'latest'})
    event_logs_log_address = event_filter_log_address.get_all_entries()
    # Get the new merkle root
    event_filter_log_merkle_root = mixer_instance.eventFilter(
        "LogMerkleRoot", {'fromBlock': 'latest'})
    event_logs_log_merkle_root = event_filter_log_merkle_root.get_all_entries()
    # Get the ciphertexts
    event_filter_log_secret_ciphers = mixer_instance.eventFilter(
        "LogSecretCiphers", {'fromBlock': 'latest'})
    event_logs_log_secret_ciphers = \
        event_filter_log_secret_ciphers.get_all_entries()
    new_merkle_root = W3.toHex(event_logs_log_merkle_root[0].args.root)[2:]
    return MixResult(
        cm_address_1=event_logs_log_address[0].args.commAddr,
        cm_address_2=event_logs_log_address[1].args.commAddr,
        new_merkle_root=new_merkle_root,
        pk_sender=event_logs_log_secret_ciphers[0].args.pk_sender,
        ciphertext_1=event_logs_log_secret_ciphers[0].args.ciphertext,
        ciphertext_2=event_logs_log_secret_ciphers[1].args.ciphertext)


def mimc_hash(instance: Any, m: bytes, k: bytes, seed: bytes) -> bytes:
    """
    Call the hash method of MiMC contract
    """
    return instance.functions.hash(m, k, seed).call()


def get_tree(instance: Any) -> List[bytes]:
    """
    Return the Merkle tree
    """
    return instance.functions.getTree().call()


def get_root(instance: Any) -> bytes:
    """
    Return the Merkle tree root
    """
    return instance.functions.getRoot().call()
