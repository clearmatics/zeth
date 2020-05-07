#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import sys
from setuptools import find_packages
from distutils.core import setup

if not hasattr(sys, 'base_prefix') or sys.base_prefix == sys.prefix:
    print("ERROR: This is not production software, install inside a venv")
    sys.exit(1)

if sys.version_info < (3, 7):
    print("ERROR: requires python >=3.7")
    sys.exit(1)

setup(
    name='zeth',
    version='0.1',
    description='Interface to zeth operations',
    packages=find_packages(),
    install_requires=[
        "mypy==0.720",
        "mypy-protobuf==1.16",
        "flake8==3.7.8",
        "pylint==2.4.3",
        "click==7.0",
        "click-default-group==1.2",
        "attrdict==2.0.1",
        "certifi==2018.11.29",
        "chardet==3.0.4",
        "cytoolz==0.9.0.1",
        "eth-abi==1.3.0",
        "eth-account==0.3.0",
        "eth-hash==0.2.0",
        "eth-keyfile==0.5.1",
        "eth-keys==0.2.1",
        "eth-rlp==0.1.2",
        "eth-typing==2.1.0",
        "eth-utils==1.4.1",
        "grpcio==1.24",
        "grpcio-tools==1.24",
        "hexbytes==0.1.0",
        "idna==2.8",
        "lru-dict==1.1.6",
        "parsimonious==0.8.1",
        "protobuf==3.6.1",
        "py_ecc==1.7.1",
        "py-solc-x==0.7.0",
        "pycryptodome==3.9.0",
        "cryptography==2.9",
        "requests==2.21.0",
        "rlp==1.1.0",
        "semantic-version==2.8.4",
        "six==1.12.0",
        "toolz==0.9.0",
        "urllib3==1.24.2",
        "web3==4.8.2",
        "websockets==6.0",
    ],
    scripts=[
        "test_commands/test_ether_mixing.py",
        "test_commands/test_erc_token_mixing.py",
        "test_commands/test_merkle_tree_contract.py",
        "commands/zeth",
    ]
)
