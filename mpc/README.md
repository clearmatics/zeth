# Overview

Tools and scripts for SRS generation via an MPC.

# Dependencies

- zeth mpc executables (an optimized build from this repo, or from a binary
  distribution).
- python3 (>=3.7) and venv (`pip install venv`).
- (Phase1 only) clone and build https://github.com/clearmatics/poweroftau
  - requires the rust build environment, including cargo

# Setup

If necessary, follow instructions to [build zeth binary](../README.md)
executables. Execute the following to install all further packages required
for the MPC:

```console
$ python -m venv env                    # create virtualenv
$ . env/bin/activate                    # activate virtualenv
(env) $ make setup                      # install
```

All commands given below assume the above virtualenv is active. If the console
has been closed between actions, reactivate the virtualenv as follows:

```console
$ . mpc/env/bin/activate
```

(Adjust the path if run from a directory other than the repo root)


# Contributor instructions

## Preparation (before MPC begins)

Create a working directory for the contribution. (Note that when contributing
multiple times to a single phase, or to multiple phases, it is recommended to
create a directory for each contribution.)

```console
(env) $ mkdir mpc_contrib
(env) $ cd mpc_contrib
```

All commands below are assumed to be executed in the working directory for the
contribution.

Generate a contributor secret key to identify yourself, and evidence of
validity:

```console
(env) $ generate_key contributor.key
```

Use the output (public key and key evidence) when registering as a participant
in the MPC. The file `contributor.key` is the contributor secret key for
signing your contribution. Keep this protected - it could be used by an
attacker to steal your place in the list of contributors, rendering your
contribution invalid.

## Contributing (during MPC)

When requested, invoke the contribution computation (ensure the env is
activated, and that commands are executed inside the working directory).
Specify the URL (you should reveive this from the coordinator, usually by email
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

(The coordinator may request that you specify other flags to these commands, to
control details of the MPC. See `phase1_contribute --help` for all available
flags.)

You will be asked to provide randomness by entering a random string and
pressing ENTER. Once this is complete, the command will automatically perform
all necessary computation, write the results to a local file and upload to the
coordinator.

As part of the execution, the contribution digest is written to stdout, as
shown above. It is also written to `response.bin.digest` in the working dir.
Keep this file (or make a note of the digest). It can be used at the end of
the process to verify that your contribution is correctly included in the final
MPC output.

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

## Generate a contribution key and certificate

Either self-signed or with a certificate chain from a trusted CA. (If using
self-signed certificates, the autority's certificate should be published and
clients instructed to download it and use the `--server-cert` flag when
contributing),

A self-signed certificate can be generated as below
```console
(env) $ openssl req -x509 \
           -nodes \
           -newkey rsa:4096 \
           -keyout key.pem \
           -out cert.pem \
           -days 365
```

## Gather contributors

Contributors should submit their email address and contribution verification
keys before the MPC begins.

## Create a configuration file

### Configuration file overview

Create the file `server_config.json` in the server working directory,
specifying properties of the MPC:
```json
// server_config.json
{
    "server": {
        "contributors_file": "contributors.json",
        "start_time": "2019-10-02 17:00:00",   # Time (server-local)
        "contribution_interval": "86400",   # 24 hours (in seconds)
        "tls_key": "key.pem",
        "tls_certificate": "cert.pem",
        "port": 8001
    }
}
```

The servers for each phase (phase1 and phase2) also support options specific to
that phase, which can be set in the config file. See the test configurations for
[phase1](../testdata/mpc_phase1_server_config.json) and
[phase2](../testdata/mpc_phase2_server_config.json) for full examples.

The `contributors_file` field must point to a file specifying the ordered set
of contributors in the MPC.  This file takes the form:
```json
{
    "contributors": [
        {
            "email": "c1@mpc.com",
            "verification_key": "308...eed4",
            "key_evidence": "015b...71d8"
        },
        {
            "email": "c2@mpc.com",
            "verification_key": "3081...0650",
            "key_evidence": "0015...25d6"
        },
        ...
    ]
}
```

See `testdata/mpc_contributors.json` for an example contributors file.

### Contributor Registration via Google Forms

The `contributors_from_csv` command can be used to generate a
`contributors.json` file from csv data output from Google Forms. Administrators
can thereby use Google Forms to allow participants to register and use this
command to automatically populate their `contributors.json` file.

Ensure that email, public key, and evidence fields are present in the form, and
download the response data as a csv file. Flags to `contributors_from_csv_` can
be used to specify the exact names of each field (see `--help` for details).

### Mail notifications

The MPC coordinator server can notify participants by email when their
contribution time slot begins (when the previous contributor either finishes
his contribution, or his timeslot expires). To enable email notifications, set
the `email_server`, `email_address` and `email_password_file` fields to point to a
(tls enabled) mail server.

## Prepare initial challenge (Phase2 only)

Phase2 requires the output from Phase1 to be processed before Phase2 can begin.
The following assumes that the Phase1 server directory is located in the
directory `../phase1_coordinator`:

```console
(env) $ phase2_prepare ../phase1_coordinator
```

Note that this process can take a significant amount of time.

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
