# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.utils import get_contracts_dir
from zeth.core.contracts import InstanceDescription
from zeth.core.mimc import MiMC7, MiMC31
from zeth.cli.utils import get_eth_network, open_web3_from_network
from os.path import join
import sys
from typing import Any


def test_mimc7(instance: Any) -> None:
    x = int(28948022309329048855892746252171976963317496166410141009864396001978282409983)  # noqa
    y = int(14220067918847996031108144435763672811050758065945364308986253046354060608451)  # noqa
    h = MiMC7().hash(x, y).to_bytes(32, 'big')

    result = instance.functions.test_mimc7(
        x.to_bytes(32, 'big'), y.to_bytes(32, 'big')).call()
    assert result == h


def test_mimc31(instance: Any) -> None:
    x = int(28948022309329048855892746252171976963317496166410141009864396001978282409983)  # noqa
    y = int(14220067918847996031108144435763672811050758065945364308986253046354060608451)  # noqa
    h = MiMC31().hash(x, y).to_bytes(32, 'big')

    result = instance.functions.test_mimc31(
        x.to_bytes(32, 'big'), y.to_bytes(32, 'big')).call()

    print(f"h={int.from_bytes(h, byteorder='big')}")
    print(f"result={int.from_bytes(result, byteorder='big')}")
    assert result == h


def main() -> int:
    web3: Any = open_web3_from_network(get_eth_network(None))
    contracts_dir = get_contracts_dir()
    contract_instance_desc = InstanceDescription.deploy(
        web3,
        join(contracts_dir, "MiMC_test.sol"),
        "MiMC_test",
        web3.eth.accounts[0],  # pylint: disable=no-member
        None,
        500000,
        {"allow_paths": contracts_dir})
    contract_instance = contract_instance_desc.instantiate(web3)

    test_mimc7(contract_instance)
    test_mimc31(contract_instance)

    print("========================================")
    print("==              PASSED                ==")
    print("========================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
