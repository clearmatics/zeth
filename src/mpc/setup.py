#!/usr/bin/env python

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
    ],
    scripts=[
        "coordinator/null_server",
        "coordinator/phase2_server",
        "coordinator/sign_contribution",
        "coordinator/generate_key",
    ]
)
