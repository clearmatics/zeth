# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.contracts import Interface
from zeth.utils import get_zeth_dir
from zeth.constants import SOL_COMPILER_VERSION
from test_commands.mock import open_test_web3
from click import command, argument
from os.path import join
from solcx import compile_files, set_solc_version
from typing import Any
from web3 import Web3  # type: ignore


@command()
@argument("deployer_address")
@argument("mint_amount", type=int)
@argument("recipient_address")
def deploy_test_token(
        deployer_address: str,
        mint_amount: int,
        recipient_address: str) -> None:
    """
    Deploy a simple ERC20 token for testing, and mint some for a specific
    address. Print the token address.
    """
    _, eth = open_test_web3()
    token_instance = deploy_token(eth, deployer_address, 4000000)
    mint_tx_hash = mint_token(
        token_instance, recipient_address, deployer_address, mint_amount)
    eth.waitForTransactionReceipt(mint_tx_hash)
    print(token_instance.address)


def compile_token() -> Interface:
    """
    Compile the testing ERC20 token contract
    """

    zeth_dir = get_zeth_dir()
    allowed_path = join(
        zeth_dir,
        "zeth_contracts/node_modules/openzeppelin-solidity/contracts")
    path_to_token = join(
        zeth_dir,
        "zeth_contracts/node_modules/openzeppelin-solidity/contracts",
        "token/ERC20/ERC20Mintable.sol")
    # Compilation
    set_solc_version(SOL_COMPILER_VERSION)
    compiled_sol = compile_files([path_to_token], allow_paths=allowed_path)
    token_interface = compiled_sol[path_to_token + ":ERC20Mintable"]
    return token_interface


def deploy_token(
        eth: Any,
        deployer_address: str,
        deployment_gas: int) -> Any:
    """
    Deploy the testing ERC20 token contract
    """
    token_interface = compile_token()
    token = eth.contract(
        abi=token_interface['abi'], bytecode=token_interface['bin'])
    tx_hash = token.constructor().transact(
        {'from': deployer_address, 'gas': deployment_gas})
    tx_receipt = eth.waitForTransactionReceipt(tx_hash)

    token = eth.contract(
        address=tx_receipt.contractAddress,
        abi=token_interface['abi'],
    )
    return token


def mint_token(
        token_instance: Any,
        spender_address: str,
        deployer_address: str,
        token_amount: int) -> bytes:
    return token_instance.functions.mint(
        spender_address,
        Web3.toWei(token_amount, 'ether')).transact({'from': deployer_address})


if __name__ == "__main__":
    deploy_test_token()  # pylint: disable=no-value-for-parameter
