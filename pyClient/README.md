# Python client to interact with the prover

## Setup

Ensure that the following are installed:

- Python 3.7 (See `python --version`)
- [venv](https://docs.python.org/3/library/venv.html#module-venv) module.
- gcc

Execute the following inside the `pyClient` directory.
```console
$ python -m venv env
$ source env/bin/activate
(env)$ make setup
```

(It may also be necessary to install solc manually if the `py-solc-x` package
fails to find it. See the instructions below.)

We assume all further commands described here are executed from within the
Python virtualenv.  To enter the virtualenv from a new terminal, re-run
```console
$ source env/bin/activate
```

## Execute unit tests

```console
(env)$ make check
```

## Execute testing client

These are scripts that perform some predetermined set of transactions between
dummy clients Alice, Bob and Charlie.

Test ether mixing:
```console
(env)$ test_ether_mixing.py [ZKSNARK]
```

Test ERC token mixing:
```console
(env)$ test_erc_token_mixing.py [ZKSNARK]
```

where `[ZKSNARK]` is the zksnark to use (must be the same as the one used on
the server).

## Install solc manually

This command might be necessary if the `py-solc-x` package cannot find `solc`
and fails to fetch it (or fails to fetch the right version).

```console
# Download the solidity compiler to compile the contracts
$ wget https://github.com/ethereum/solidity/releases/download/[solc-version]/[solc-for-your-distribution] \
    -O $ZETH/pyClient/zeth-devenv/lib/[python-version]/site-packages/solcx/bin/solc-[solc-version]
$ chmod +x $ZETH/pyClient/zeth-devenv/lib/[python-version]/site-packages/solcx/bin/solc-[solc-version]
```

To run this command, replace the solidity version (denoted by `[solc-version]`),
the python version (denoted by `[python-version]`), and binary file (denoted by
`[solc-for-your-distribution]`) by your system specific information.

# The `zeth` command line interface

The `zeth` command exposes Zeth operations via a command line interface.  A
brief description is given in this section.  More details are available via
`zeth --help`, and example usage can be seen in the [pyclient test
script](../scripts/test_zeth_cli).

## Environment

Depending on the operation being performed, the `zeth` client must:
- interact with an Ethereum RPC host
- interact with the deployed Zeth contracts
- request proofs and keys from the `prover_server`, and
- access secret and public data for the current user

Some of this data could not easily be specified by command line, so the `zeth`
tools assume it can be found in specific files (with default file names,
overridable on the command line).

The set of files required by zeth for a single user is described below.  We
recommend creating a directory for each user, containing these files.  In this
way, it is very easy to setup one or more conceptual "users" and invoke `zeth`
operations on behalf of each of them to experiment with the system.

- `eth-address` specifies an eth address from which to fund transactions.  When
  running the testnet (as described in the [top-level README](../README.md)),
  addresses are created at startup and written to the console.  One of these can
  be copy-pasted into this file.
- `zeth-instance.json` contains the address and interface for an instance of the
  zeth contracts.  This file is created by the deployment step below and should
  be distributed to each client.
- `zeth-key.json` and `zeth-key.json.pub` hold the secret and public Zeth keys
  for the client.  These can be generated with the `zeth key` command.
  `zeth-key.json.pub` represents the public address of the client.  This can be
  shared freely, allowing other users to privately transfer funds to this
  client.  The secret `zeth-key.json` should **not** be shared.

## Deployment

Deployment compiles and deploys the contracts and initializes them with
appropriate data to create a new empty instance of the Zeth mixer.  It requires
only an `eth-address` file mentioned above, where the address has sufficient
funds.

```console
# Create a clean directory for the deployer
(env)$ mkdir deployer
(env)$ cd deployer

# Specify an eth-address file for an (unlocked) Ethereum account
(env)$ echo 0x.... > eth-address

# Compile and deploy
(env)$ zeth deploy

# Share the instance file with all clients
$ cp zeth-instance.json <destination>
```

## User setup

To set up her client, Alice must setup all client files mentioned above:
```console
# Create a clean client directory
$ mkdir alice
$ cd alice

# Specify an eth-address file for an (unlocked) Ethereum account
$ echo 0x.... > eth-address

# Copy the instance file (received from the deployer)
$ cp <shared-instance-file> zeth-instance.json

# Generate new secret (zeth-key.json) and public key (zeth-key.json.pub)
$ zeth key

# Share the public address with other users
$ cp zeth-key.json.pub <destination>
```

With these files in place, `zeth` commands invoked from inside this directory
can perform actions on behalf of Alice.  We call this Alice's *client directory*
below, and assume that all commands are executed in a directory with these
files.

## Receiving transactions

The following command scans the blockchain for any new transactions addressed to
the public key `zeth-key.json.pub`:

```console
# Check all new blocks for notes addressed to `zeth-key.json.pub`, storing them
# in the ./notes directory.
(env)$ zeth sync
```

Any notes found are stored in the `./notes` directory, as files containing the
secret data required to spend them.  This forms a very primitive Zeth "wallet".

```console
# List all notes received by this client
$ zeth notes
```
lists information about all known notes belonging to the current user.

## Mix command

The `zeth mix` command is used to interact with a deployed Zeth instance.  The
command accepts the following information:

**Input Notes.** Zeth notes owned by the current client, which should be visible
via `zeth notes`.  Either the integer "address" or the truncated commitment
value (8 hex chars) can be used to specify which notes to use as inputs.

**Output Notes.** Given as pairs of Zeth public key and value, separated by a
comma `,`.  The form of the public key is exactly as in the `zeth-key.json.pub`
file.  That is, two 32 byte hex values separated by a colon `:`.

**Public Input.** Ether or ERC20 token value send to the mixer.

**Public Output.** Ether or ERC20 tokens value to be extracted from the mixer.

Some examples are given below

### Depositing funds

A simple deposit consists of some public input (ether or tokens), and the
creation of a private note.

```console
# Deposit 10 ether from `eth-address`, creating a Zeth note owned by Alice
(env)$ zeth mix --out <public_key>,10 --vin 10
```
where `<public-key>` is the contents of `zeth-key.json.pub`.

### Privately send a ZethNote to another user

To privately transfer value within the mixer, no public input / output is
required.  Unspent notes (inputs) and destination addresses and values are
specified.

```console
$ zeth notes
b1a2feaf: value=200, addr=0
eafe5f84: value=100, addr=2

$ zeth mix \
    --in eafe5f84 \                       # "eafe5f84: value=100, addr=2"
    --in 0 \                              # "b1a2feaf: value=200, addr=0"
    --out d77f...0e00:cc7c....7f76,120 \  # 120 to this addr
    --out 3a43...fd3b:9fc8....b838,180    # 180 to this addr
```

### Withdrawing value from notesa

Specify the note(s) to be withdrawn, and the total value as public output:
```console
$ zeth withdraw --in eafe5f84 --vout 100
```

### Complex Transactions

Public and private inputs and outputs can all be specified for a single
transaction.  Combining multiple operations can help to obfuscate the meaning of
the transaction.

### Async transactions

The `mix` command broadcasts transactions to the Ethereum network and by default
output the transaction ID.  Users can wait for these transactions to be accepted
into the blockchain by passing this ID to the `zeth sync` command via the
`--wait-tx` flag.  This command waits for the transaction to be committed and
then searches for new notes.

Alternatively, the `--wait` flag can be passed to the `mix` command to make it
wait and sync new notes before exiting.

## Limitations - Note and Key management

As proof-of-concept software, these tools are not suitable for use in a
production environment and have several functional limitations.  Some of those
limitations are mentioned here.

The `zeth` tool suite does not track which of the client's notes have been spent
by previous operations.  In the presence of async transactions and possible
forks in the chain, such tracking logic would greatly increase the complexity of
the client tools and is considered out of scope for this proof-of-concept.  The
user must manually track which notes have been spent (for example by moving
their files into a `spent` subdirectory where they will not be seen by the
wallet).

All values that make up the zeth secret key, and secrets (required to spend
notes) are stored in plaintext.  A fully secure client would encrypt these to
protect them from malicious entities that may gain access to the file system.
Such client-side security mechanisms are also beyond the scope of this
proof-of-concept implementation.

Similarly, such key and note data is not automatically backed up or otherwise
protected by these tools.
