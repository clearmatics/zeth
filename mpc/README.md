# Overview

Tools and scripts for SRS generation via an MPC.

# Dependencies

- zeth mpc executables (built from this repo, or from a binary distribution)
- python3 (>=3.6) and venv (`pip install venv`).
- (Phase1 only) clone and build https://github.com/clearmatics/poweroftau
  - requires the rust build environment, including cargo

# Setup

If necessary, follow instructions to [build zeth binary](../README.md)
executables.  Execute the following to install all further packages required
for the MPC:

```console
$ pyton -m venv env                     # create virtualenv
$ . env/bin/activate                    # activate virtualenv
(env) $ make setup                      # install
```

All commands given below assume the above virtualenv is active.  If the console
has been closed between actions, reactivate the virtualenv as follows:

```console
$ . mpc/env/bin/activate
```

(Adjust the path if run from a directory other than the repo root)


# Contributor instructions

## Preparation (before MPC begins)

Create a working directory for the contribution.  (Note that when contributing
multiple times to a single phase, or to multiple phases, it is recommended to
create a directory for each contribution.)

```console
(env) $ mkdir mpc_contrib
(env) $ cd mpc_contrib
```

Generate a contributor secret key to identify youself.

```console
(env) $ generate_key contributor.key > contributor.pub
```

`contributor.pub` should contain contribution verification key (public key) for
the contributor.  Use the contents when registering as a participant in the
MPC.  `contributor.key` is the contributor secret key for signing your
contribution.  Keep this protected - it could be used by an attacker to steal
your place in the list of contributors, rendering your contribution invalid.

## Contributing (during MPC)

When requested, invoke the contribution computation from inside the working
directory, specifying the URL (received from the coordinator, usually by email
or during registration), and the contributor secret key.

For phase1:
```console
(env) $ phase1_contribute https://<host>[:<port>] contributor.key
...
Digest of the contribution was:
00a769dc 5bce6cd6 8e679d5e b7f1f175
e410759e 33eb11b4 0fff9cb6 2d082165
8bfd09fe d8e10f51 3bd05cfa e7cb92cb
29ff0501 e51ff07e 3088a817 7a6ddb55
Digest written to: response.bin.digest
...
```

For phase2:
```console
(env) $ phase1_contribute https://<host>[:<port>] contributor.key
...
Digest of the contribution was:
00a769dc 5bce6cd6 8e679d5e b7f1f175
e410759e 33eb11b4 0fff9cb6 2d082165
8bfd09fe d8e10f51 3bd05cfa e7cb92cb
29ff0501 e51ff07e 3088a817 7a6ddb55
Digest written to: response.bin.digest
...
```

(The coordinator may specify other flags to these commands, to control details
of the MPC).

You may be asked to provide randomness by entering a random string and pressing
ENTER.  Once this is complete, the command will automatically perform all
necessary computation, write the results to a local file and upload to the
coordinator.

As part of the execution, the contribution digest is written to stdout, as
shown above.  It is also written to `response.bin.digest`.  Keep this file (or
make a note of the digest).  It can be used to verify that your contribution is
correctly included in the final MPC output.

# Coordinator Instructions

## Create a server working directory

```console
(env) $ mkdir phase1_coordinator
(env) $ cd phase1_coordinator
```
or
```console
(env) $ mkdir phase2_coordinator
(env) $ cd phase2_coordinator
```

## Generate a key and certificate

Either self-signed (in which case, the certificate should be published and
clients instructed to download it and use the `--server-cert` flag when
contributing), or with a certificate chain from a trusted CA.

A self-signed certificate can be generated as below
```console
(env) $ openssl req -x509 \
           -nodes \
           -newkey rsa:4096 \
           -keyout key.pem \
           -out cert.pem \
           -days 365
```

## Gather contributor registration

Contributors should submit their email address and contribution verification
keys before the MPC begins.

## Create a configuration file

Create the file `server_config.json` in the server working directory.  This
should list the ordered set of contributors, as well as other properties of the
MPC:
```console
// server_config.json
{
    "contributors": [
        {
            "email": "c1@mpc.com",
            "public_key": "3081...eed4"
        },
        {
            "email": "c2@mpc.com",
            "public_key": "3081...0650"
        },
        {
            "email": "c3@mpc.com",
            "public_key": "3081...f876"
        },
        {
            "email": "c4@mpc.com",
            "public_key": "3081...0118"
        }
    ],
    "start_time": "2019-10-02 17:00:00",   # Time (server-local)
    "contribution_interval": "86400",   # 24 hours (in seconds)
    "tls_key": "key.pem",
    "tls_certificate": "cert.pem",
    "port": 8001
}
```

The server can notify participants by email when their contribution time slot
begins (when the previous contributor either finishes his contribution, or his
timeslot expires).  To enable email notifications, set the `email_server`,
`email_address` and `email_password` fields to point to an (tls enabled) mail
server.

See the [test configuration](../testdata/mpc_server_config.json) for an example
configuration file.

## Prepare initial challenge (Phase2 only)

Phase2 requires the output from Phase1 to be processed before Phase2 can begin.
The following assumes that the phase1 server directory is located
`../phase1_coordinator`, and contains phase1 output `pot-2097152.bin`.

```console
(env) $ phase2_prepare .../phase1_coordinator/pot-2097152.bin
```

## Launch the server

Launch either `phase1_server` or `phase2_server` in the server working
directory.

```console
(env) $ phase1_server
```
or
```console
(env) $ phase2_server
```


# Run tests

From the repository root, with the virutalenv activated:

```console
(env) $ cd mpc
(env) $ make check
```
