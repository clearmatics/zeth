# Python client to interact with the prover

## Setup

Ensure that the following are installed:

- Python 3.7  (See `python --version`)
- [venv](https://docs.python.org/3/library/venv.html#module-venv) module.
- gcc

It may also be necesssary to install solc manually if the `py-solc-x` package
fails to find it. See the instructions below.

```console
$ python -m venv env
$ source env/bin/activate
(env)$ make setup
```

## Execute unit tests

```console
(env)$ make check
```

## Execute testing client

Test ether mixing:
```console
test_ether_mixing.py [ZKSNARK]
```

Test ERC token mixing
```console
test_erc_token_mixing.py [ZKSNARK]
```

where `[ZKSNARK]` is the zksnark to use (must be the same as the one used on
the server).

## Install solc manually

This command might be necessary if the `py-solc-x` package cannot find `solc`
and fails to fetch it (or fails to fetch the right version).

```console
# Download the solidity compiler to compile the contracts
$ wget https://github.com/ethereum/solidity/releases/download/[solc-version]/[solc-for-your-distribution] -O $ZETH/pyClient/zeth-devenv/lib/[python-version]/site-packages/solcx/bin/solc-[solc-version]
$ chmod +x $ZETH/pyClient/zeth-devenv/lib/[python-version]/site-packages/solcx/bin/solc-[solc-version]
```

To run this command you need to replace the solidity version (denoted by
`[solc-version]`), the python version (denoted `[python-version]`), and binary
file (denoted by `[solc-for-your-distribution]`) by your system specific pieces
of information.
