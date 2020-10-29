#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import sys
from setuptools import find_packages
from distutils.core import setup


if not hasattr(sys, 'base_prefix') or sys.base_prefix == sys.prefix:
    print("ERROR: This is not production software, install inside a venv")
    exit(1)

if sys.version_info < (3, 7):
    print("ERROR: requires python >=3.7")
    exit(1)


setup(
    name='coordinator',
    version='0.5',
    description='MPC Coordinator for Zeth SRS',
    packages=find_packages(),
    install_requires=[
        "mypy==0.720",
        "flake8==3.7.8",
        "pylint==2.4.3",
        "flask==1.1.1",
        "cheroot==7.0.0",
        "pycryptodome==3.9.0",
        "ecdsa==0.13.3",
        "click==7.0",
        "requests==2.22.0",
    ],
    scripts=[
        "commands/phase1_server",
        "commands/phase1_contribute",
        "commands/phase2_prepare",
        "commands/phase2_server",
        "commands/phase2_contribute",
        "commands/get_challenge",
        "commands/upload_contribution",
        "commands/sign_contribution",
        "commands/generate_key",
        "commands/public_key",
        "commands/contributors_from_csv",
        "commands/create_keypair",
    ]
)
