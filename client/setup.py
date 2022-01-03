#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
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
    version='0.8',
    description='Interface to zeth operations',
    packages=find_packages(),
    install_requires=[
        "mypy==0.790",
        "mypy-protobuf==1.23",
        "flake8==3.8.3",
        "pylint==2.9",
        "click==7.0",
        "click-default-group==1.2",
        "grpcio==1.33.2",
        "grpcio-tools==1.33.2",
        "protobuf==3.13.0",
        "py_ecc==1.7.1",
        "py-solc-x==1.1.0",
        "cryptography==3.3.2",
        "web3>=5<6",
    ],
    entry_points={
        'console_scripts': [
            'zeth-helper=zeth.helper.zeth_helper:zeth_helper',
            'zeth=zeth.cli.zeth:zeth',
        ],
    }
)
