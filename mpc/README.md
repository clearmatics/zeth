# Overview

Tools and scripts for SRS generation via an MPC.

# Dependencies

- zeth mpc executables (built from this repo, or from a binary distribution)
- python3 (>=3.6) and venv (`pip install venv`).

# Common Setup

If necessary, follow instructions to [build zeth binary](../README.md)
executables.  Then install all packages required for the MPC:

```
$ pyton -m venv env
$ . env/bin/activate
(env) $ make setup
```

Ensure all other commands are executed within the virtualenv.

## Contributor common setup

Create a working directory
```
(env) $ mkdir mpc_work
(env) $ cd mpc_work
```

Generate a key to identify youself as a contributor
```
(env) $ generate_key contributor.key > contributor.pub
```

`contributor.pub` now contains the human-readable representation of the
verification key (or public key) for the contributor.  Use `contributor.pub` to
register as a participant in the MPC.  Keep `contributor.key` protected - this
is the signing (or PRIVATE) key that could be used by an attacker to steal your
place in the list of contributors, rendering your contribution invalid.

# Phase1 (Powers of Tau)

## Contributors

## Coordinator

# Phase2

## Contributors

When requested, invoke the contribution computation from inside the working
directory (`mpc_work` above), specifying the URL (specified by the
coordinator), and the key identifying this contributor.

```
(env) $ phase2_contribute http://<host>[:<port>] contributor.key
...
Digest of the contribution was:
00a769dc 5bce6cd6 8e679d5e b7f1f175
e410759e 33eb11b4 0fff9cb6 2d082165
8bfd09fe d8e10f51 3bd05cfa e7cb92cb
29ff0501 e51ff07e 3088a817 7a6ddb55
Digest written to: response.bin.digest
...
```

As part of the execution, the contribution digest is written to stdout and to
`response.bin.digest`.  Keep this file (or make a note of the digest).  It can
be used to verify that your contribution is corectly included in the final MPC
output.

## Coordinator

# Run tests

```
(env) $ make check
```

## Run the coordinator

Inside the venv:
```
(env) $ server
```
