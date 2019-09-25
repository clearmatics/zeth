# Overview

Tools and scripts for SRS generation via an MPC.

# Dependencies

- zeth mpc executables (built from this repo, or from a binary ditribution)
- python3 (>=3.6) and venv (`pip install venv`).

# For MPC Participants

## Contributing

## Verification

# For MPC Coordinator

## Setup

If necessary, follow instructions to build zeth binary executables.  Then:

```
$ pyton -m venv env
$ . env/bin/activate
(env) $ make setup
```

# Run tests

```
(env) $ make check
```

## Run the coordinator

Inside the venv:
```
(env) $ server
```
