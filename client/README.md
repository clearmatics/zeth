# Python client to interact with the prover

## Setup

Ensure that the following are installed:

- Python 3.7 (See `python --version`)
- [venv](https://docs.python.org/3/library/venv.html#module-venv) module.
- gcc

Execute the following inside the `client` directory.
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

These are scripts that perform some predetermined transactions between a set of
users: Alice, Bob and Charlie.

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

## Note on solc compiler installation

Note that `make setup` will automatically install the solidity compiler in `$HOME/.solc`
(if required) and not in the python virtual environment.

# The `zeth` command line interface

The `zeth` command exposes Zeth operations via a command line interface.  A
brief description is given in this section.  More details are available via
`zeth --help`, and example usage can be seen in the [pyclient test
script](../scripts/test_zeth_cli).

## Environment

Depending on the operation being performed, the `zeth` client must:
- interact with an Ethereum RPC host,
- interact with the deployed Zeth contracts,
- request proofs and proof verification keys from `prover_server`, and
- access secret and public data for the current user

Quite a lot of information must be given in order for the client to do this,
and the primary and auxiliary inputs to a Zeth operation are generally very
long. It can therefore be difficult to pass this information to the zeth
commands as command-line arguments. Thus, such data is stored in files with
default file names (which can be overridden on the zeth commands).

The set of files required by Zeth for a single user to interact with a specific
deployment is described below. We recommend creating a directory for each
user/Zeth deployment, containing the following files. In this way, it is very
easy to setup one or more conceptual "users" and invoke `zeth` operations on
behalf of each of them to experiment with the system.

- `eth-address` specifies an Ethereum address from which to transactions should
  be funded. When running the testnet (see [top-level README](../README.md)),
  addresses are created at startup and written to the console. One of these can
  be copy-pasted into this file.
- `zeth-instance.json` contains the address and ABI for a single instance of
  the zeth contract. This file is created by the deployment step below and
  should be distributed to each client that will use this instance.
- `zeth-address.json` and `zeth-address.json.pub` hold the secret and public
  parts of a ZethAddress. These can be generated with the `zeth gen-address`
  command. `zeth-address.json.pub` holds the public address which can be shared
  with other users, allowing them to privately transfer funds to this client.
  The secret `zeth-address.json` should **not** be shared.

Note that by default the `zeth` command will also create a `notes`
subdirectory to contain the set of notes owned by this user. These are also
specific to a particular Zeth deployment.

Thereby, in the case of a Zeth user interacting with multiple Zeth deployments
(for example one for privately transferring Ether, and another for an ERC20
token), a directory should be created for each deployment:

```
  MyZethInstances/
      Ether/
          eth-address
          zeth-instance.json
          zeth-address.json
          zeth-address.json.pub
          notes/...
      ERCToken1/
          eth-address
          zeth-instance.json
          zeth-address.json
          zeth-address.json.pub
          notes/...
```

`zeth` commands invoked inside `MyZethInstances/Ether` will target the Zeth
deployment that handles Ether. Similarly, commands executed inside
`MyZethInstances/ERCToken1` will target the deployment that handles the token
"ERCToken1".

## Deployment

Deployment compiles and deploys the contracts and initializes them with
appropriate data to create a new instance of the Zeth mixer. It requires only
an `eth-address` file mentioned above, where the address has sufficient funds.

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

# Generate new Zeth Address with secret (zeth-address.json) and
# public address (zeth-address.json.pub)
$ zeth gen-address

# Share the public address with other users
$ cp zeth-address.json.pub <destination>
```

With these files in place, `zeth` commands invoked from inside this directory
can perform actions on behalf of Alice.  We call this Alice's *client directory*
below, and assume that all commands are executed in a directory with these
files.

## Receiving transactions

The following command scans the blockchain for any new transactions which
generate Zeth notes indended for the public address `zeth-address.json.pub`:

```console
# Check all new blocks for notes addressed to `zeth-address.json.pub`,
# storing them in the ./notes directory.
(env)$ zeth sync
```

Any notes found are stored in the `./notes` directory as individual files.
These files contain the secret data required to spend the note.

```console
# List all notes received by this client
$ zeth ls-notes
```
lists information about all known notes belonging to the current user.

## Mix command

The `zeth mix` command is used to interact with a deployed Zeth Mixer instance.
The command accepts the following information:

**Input Notes.** Zeth notes owned by the current client, which should be visible
via `zeth ls-notes`.  Either the integer "address" or the truncated commitment
value (8 hex chars) can be used to specify which notes to use as inputs.

**Output Notes.** Given as pairs of Zeth public address and value, separated by
a comma `,`. The form of the public address is exactly as in the
`zeth-address.json.pub` file. That is, two 32 byte hex values separated by a
colon `:`.

**Public Input.** Ether or ERC20 token value to deposit in the mixer.

**Public Output.** Ether or ERC20 tokens value to be withdrawn from the mixer.

Some examples are given below

### Depositing funds

A simple deposit consists of some public input (ether or tokens), and the
creation of Zeth notes.

```console
# Deposit 10 ether from `eth-address`, creating Zeth notes owned by Alice
(env)$ zeth mix --out <public-zeth-address>,10 --vin 10
```
where `<public-zeth-address>` is the contents of `zeth-address.json.pub`.

### Privately send a ZethNote to another user

To privately transfer value within the mixer, no public input / output is
required. Unspent notes (inputs) and destination addresses and output note
values are specified.

```console
$ zeth ls-notes
b1a2feaf: value=200, addr=0
eafe5f84: value=100, addr=2

$ zeth mix \
    --in eafe5f84 \                       # "eafe5f84: value=100, addr=2"
    --in 0 \                              # "b1a2feaf: value=200, addr=0"
    --out d77f...0e00:cc7c....7f76,120 \  # 120 to this addr
    --out 3a43...fd3b:9fc8....b838,180    # 180 to this addr
```

### Withdrawing funds from the mixer

Specify the note(s) to be withdrawn, and the total value as public output:
```console
$ zeth mix --in eafe5f84 --vout 100
```

### A note on the `zeth mix` command

As explained above, the `zeth mix` command can be used to deposit funds on the
mixer, transfer notes, and withdraw funds from the mixer. A single command can
perform all of these in one transaction, which greatly improves the privacy
level provided by Zeth. In fact, no exact information about the meaning of a
transaction is ever leaked to the an observant attacker.

Here are a few examples of complex payments allowed by `zeth mix`:

```console
$ zeth ls-notes
b1a2feaf: value=200, addr=0
eafe5f84: value=100, addr=2

$ zeth mix \
    --in eafe5f84 \                       # "eafe5f84: value=100, addr=2"
    --vin 5 \
    --out d77f...0e00:cc7c....7f76,103 \  # 103 to this address (e.g. Bob)
    --out 3a43...fd3b:9fc8....b838,2      # 2 to another addr (e.g. my refund)

zeth mix \
    --in eafe5f84 \                       # "eafe5f84: value=100, addr=2"
    --out d77f...0e00:cc7c....7f76,98.5 \ # 98.5 to this address (e.g. Bob)
    --vout 1.5
```

### Async transactions

The `mix` command broadcasts transactions to the Ethereum network and by default
output the transaction ID.  Users can wait for these transactions to be accepted
into the blockchain by passing this ID to the `zeth sync` command via the
`--wait-tx` flag.  This command waits for the transaction to be committed and
then searches for new notes.

Alternatively, the `--wait` flag can be passed to the `mix` command to make it
wait and sync new notes before exiting.

## Limitations - Note and Address management

As proof-of-concept software, these tools are not suitable for use in a
production environment and have several functional limitations. Some of those
limitations are mentioned here.

The `zeth` tool suite does not track which of the client's notes have been
spent by previous operations. In the presence of async transactions and
possible forks in the chain, such tracking logic would greatly increase the
complexity of the client tools and is considered out of scope for this
proof-of-concept. The user must manually track which notes have been spent (for
example by moving their files into a `spent` subdirectory where they will not
be seen by the wallet).

All values that make up the Zeth secret address, and Zeth note data (required
to spend notes) are stored in plaintext. A fully secure client would encrypt
these to protect them from malicious entities that may gain access to the file
system. Such client-side security mechanisms are also beyond the scope of this
proof-of-concept implementation.

Similarly, such address and note data is not automatically backed up or
otherwise protected by these tools.
