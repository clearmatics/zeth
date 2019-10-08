#!/usr/bin/env python3

import sys
from setuptools import find_packages
from distutils.core import setup


if not hasattr(sys, 'base_prefix') or sys.base_prefix == sys.prefix:
    print("ERROR: This is not production software, install inside a venv")
    exit(1)


setup(
    name='coordinator',
    version='0.1',
    description='MPC Coordinator for Zeth SRS',
    packages=find_packages(),
    install_requires=[
        "mypy==0.720",
        "flake8==3.7.8",
        "flask==1.1.1",
        "cheroot==7.0.0",
        "pycryptodome==3.9.0",
        "ecdsa==0.13.2",
        "click==7.0",
        "requests==2.22.0",
    ],
    scripts=[
        "commands/phase1_server",
        "commands/phase1_contribute",
        "commands/phase2_server",
        "commands/phase2_contribute",
        "commands/sign_contribution",
        "commands/generate_key",
        "commands/public_key",
    ]
)
