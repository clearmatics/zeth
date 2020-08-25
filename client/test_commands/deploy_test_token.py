# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.contracts import Interface, send_contract_call
from zeth.utils import EtherValue, get_zeth_dir, open_web3
from zeth.constants import SOL_COMPILER_VERSION
from commands.utils import load_eth_address, load_eth_private_key
from commands.constants import ETH_ADDRESS_DEFAULT
from click import command, argument, option, pass_context
from os.path import join
from solcx import compile_files, set_solc_version
from typing import Optional, Any


@command()
@option(
    "--eth-addr",
    help=f"Address or address filename (default: {ETH_ADDRESS_DEFAULT})")
@option("--eth-private-key", help="Sender's eth private key file")
@argument("mint_amount", type=int)
@argument("recipient_address")
@pass_context
def deploy_test_token(
        ctx: Any,
        eth_addr: Optional[str],
        eth_private_key: Optional[str],
        mint_amount: int,
        recipient_address: str) -> None:
    """
    Deploy a simple ERC20 token for testing, and mint some for a specific
    address. Print the token address.
    """
    eth_addr = load_eth_address(eth_addr)
    eth_private_key_data = load_eth_private_key(eth_private_key)
    recipient_address = load_eth_address(recipient_address)
    web3 = open_web3(ctx.obj["eth_rpc_endpoint"])
    token_instance = deploy_token(
        web3, eth_addr, eth_private_key_data, EtherValue(4000000, 'wei'))  \
        # pylint: disable=no-member
    mint_tx_hash = mint_token(
        web3,
        token_instance,
        recipient_address,
        eth_addr,
        eth_private_key_data,
        EtherValue(mint_amount, 'ether'))
    web3.eth.waitForTransactionReceipt(mint_tx_hash)
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
        web3: Any,
        deployer_address: str,
        deployer_private_key: Optional[bytes],
        deployment_gas: Optional[EtherValue]) -> Any:
    """
    Deploy the testing ERC20 token contract
    """
    token_interface = compile_token()
    token = web3.eth.contract(
        abi=token_interface['abi'], bytecode=token_interface['bin'])
    constructor_call = token.constructor()
    tx_hash = send_contract_call(
        web3=web3,
        call=constructor_call,
        sender_eth_addr=deployer_address,
        sender_eth_private_key=deployer_private_key,
        gas=deployment_gas)
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)

    token = web3.eth.contract(
        address=tx_receipt.contractAddress,
        abi=token_interface['abi'],
    )
    return token


def mint_token(
        web3: Any,
        token_instance: Any,
        spender_address: str,
        deployer_address: str,
        deployer_private_key: Optional[bytes],
        token_amount: EtherValue) -> bytes:
    mint_call = token_instance.functions.mint(spender_address, token_amount.wei)
    return send_contract_call(
        web3=web3,
        call=mint_call,
        sender_eth_addr=deployer_address,
        sender_eth_private_key=deployer_private_key)
