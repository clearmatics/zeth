# Zeth - Zerocash on Ethereum

:rotating_light: **WARNING** This project is a Proof of Concept. It is highly inefficient and has not been thoroughly reviewed. Please do not use in production!

**Disclaimer:** This work is inspired from [babyzoe](https://github.com/zcash-hackworks/babyzoe), [Miximus](https://github.com/barryWhiteHat/miximus.git).
It follows and extends the design presented in [zerocash-ethereum](https://github.com/AntoineRondelet/zerocash-ethereum) by adapting some code initially written by [Zcash](https://github.com/zcash/zcash).

:point_right: Check our [paper](https://arxiv.org/pdf/1904.00905.pdf), and the [protocol specifications](https://github.com/clearmatics/zeth-specifications) for more information about Zeth.

:raising_hand: Want to propose a protocol change? Amazing! Please consider writing a [Zeth Protocol Improvement Proposal (ZPIP)](https://github.com/clearmatics/zpips).

## Building and running the project:

:computer: **Warning** This project primarily targets x86_64 Linux and macOS platforms.

### Environment

In order to follow the README below, you will need:
- [Docker](https://www.docker.com/get-started)
- [Npm](https://www.npmjs.com/get-npm) (at least version `6.9.0`)
- [Node](https://nodejs.org/en/) (recommended version `v10` to be able to build and use the custom `ganache-cli`)
- [Python3](https://www.python.org/downloads/) (at least version `3.7`)
- [Pip](https://pip.pypa.io/en/stable/) (at least version `19.0.2`)

Additionally, several tools from the GCC and LLVM tools suite are used to improve code quality and generate the documentation of the project. These are required in order to compile the project with all options enabled:
- [Doxygen](http://www.doxygen.nl/)
- [clang-format](https://clang.llvm.org/docs/ClangFormat.html)
- [clang-tidy](https://clang.llvm.org/extra/clang-tidy/)
- [cppcheck](http://cppcheck.sourceforge.net/)
- [include-what-you-use](https://include-what-you-use.org/)
- [llvm-symbolizer](https://llvm.org/docs/CommandGuide/llvm-symbolizer.html)

To use the Zeth functionality, 3 components are required:
- An Ethereum network (the commands below use a local testnet) to host the Zeth
  contracts and handle transactions.
- A running "prover_server" process, used by Zeth clients to generate proofs.
- Client tools, which generate all inputs required for a Zeth operations,
  request proofs from the "prover_server", and transmit transactions to the
  Ethereum network holding the Zeth contract.

We use 3 terminals, one for each of the above components.

Note: Mac users should increase docker runtime memory from 2GB to 4GB to allow Terminal 1 to complete successfully.

#### Terminal 1:

We propose 2 alternatives to run the `prover_server` below.

##### Fetch the prover_server image (recommended)

```bash
docker pull clearmatics/zeth-prover:latest
docker run -ti -p 50051:50051 --name prover zeth-prover:latest prover_server
```

##### Build and run the prover_server in the development container

```bash
# Clone this repository:
git clone git@github.com:clearmatics/zeth.git
cd zeth

# Build the zeth-dev image
docker build -f Dockerfile-dev -t zeth-dev .
# Start the zeth development container
docker run -ti -p 50051:50051 --name zeth zeth-dev:latest

# All the commands below are run in the docker container
# Configure your environment
. ./setup_env.sh

# Compile the proving server
mkdir build
cd build
cmake .. [<flags (see below)>]
# Compile all libraries and tools, including the prover_server
make
# (optional) Run the unit tests
make test
# (optional) Run the all tests (unit tests, syntax checks, etc)
make check

# Start the prover_server process
prover_server
```

Note: By default, `prover_server` generates a key at startup. Flags can be used
to force the server to load and/or save keys. Run `prover_server --help`
for more details.

##### Build Options

Some flags to the `cmake` command can control the build configuration.
`-DCMAKE_BUILD_TYPE=Release` or `-DCMAKE_BUILD_TYPE=Debug` can be used to force
a release or debug build.

By default, zeth makes use of the GROTH16 zk-snark. To chose a different
zksnark run the following: ``` cmake -DZETH_SNARK=$ZKSNARK .. ``` where
`$ZETH_SNARK` is `PGHR13` (see https://eprint.iacr.org/2013/279,
http://eprint.iacr.org/2013/879) or `GROTH16`(see
https://eprint.iacr.org/2016/260).

#### Terminal 2: Ethereum testnet

```bash
# Start the Ethereum test net by running the following commands
cd zeth_contracts

# If the install below fails with python errors, try running:
npm config set python python2.7

# Install dependencies
npm install

# Start a local Ethereum testnet
npm run testrpc
```

#### Terminal 3: Python client

```bash
# Configure your environment
. ./setup_env.sh

cd client
```

Follow the steps described in the [client README](client/README.md) to run
tests or invoke the zeth tools.

## Secure Multi Party Computation for the Groth16 SRS generation

See [MPC for SRS generation documentation](mpc/README.md)

## Development dependencies (for building outside of the Docker container)

Immediate dependencies are provided as submodules and compiled during
the Zeth build. Ensure submodules are synced.

The following libraries are also required to build:

- grpc
- gmp
- boost
- openssl

## Generate the Doxygen documentation

To generate the documentation of Zeth:
```bash
cd build
cmake .. -DGEN_DOC=ON && make docs
```

## Compile the project using 'sanitizers'

You can select the sanitizer of your choice (one of the sanitizers listed [here](./cmake/sanitizers.cmake)) by passing the flag `-DSANITIZER=<sanitizer>` to `cmake`.

Example:
```bash
cd build
cmake -DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_CXX_COMPILER=/usr/bin/clang++ -DSANITIZER=Address -DCMAKE_BUILD_TYPE=Debug ..
make check
```

## Docker images
| Docker files | Image | Tags | Description |
|---------------|------|-----|--|
| [./Dockerfile-prover](./Dockerfile-prover) | [clearmatics/zeth-prover](https://hub.docker.com/r/clearmatics/zeth-prover) | `latest`, `vX.Y.Z` - Release of zeth, `git-%HASH%` - developers build by git-commit  | [Zeth Prover Server](./prover_server/README.md). Image use `zeth-base` for building |
| [./Dockerfile-client](./Dockerfile-client) | [clearmatics/zeth-client](https://hub.docker.com/r/clearmatics/zeth-client) | `latest`, `vX.Y.Z` - Release of zeth, `git-%HASH%` - developers build by git-commit  | [Python client to interact with the prover](./client/README.md) |
| [./Dockerfile-mpc](./Dockerfile-mpc) | [clearmatics/zeth-mpc](https://hub.docker.com/r/clearmatics/zeth-mpc) | `latest`, `vX.Y.Z` - Release of zeth, `git-%HASH%` - developers build by git-commit  | [Tools for Multi-Party Computation](./mpc/README.md). Image use `zeth-base` for building |
| [./Dockerfile-base](./Dockerfile-base) | [clearmatics/zeth-base](https://hub.docker.com/r/clearmatics/zeth-base) | `latest`, `vA.B.C` - Release of zeth-base | Base image for building other containers |



## Run analysis tools on the code

Several tools can be ran on the code. These can be enabled via a set of compilation options.

Note: The `clang-tidy` target runs a clang-tidy python script that should be fetched from [here](https://github.com/llvm/llvm-project/blob/master/clang-tools-extra/clang-tidy/tool/run-clang-tidy.py). To do so, run: `cd build && wget https://raw.githubusercontent.com/llvm/llvm-project/master/clang-tools-extra/clang-tidy/tool/run-clang-tidy.py`

Example:
```bash
# run-clang-tidy.py needs to be in the PATH to be found
PATH=$PATH:${PWD}
chmod +x run-clang-tidy.py

cmake -DUSE_CLANG_FORMAT=ON -DUSE_CPP_CHECK=ON -DUSE_CLANG_TIDY=ON ..
make cppcheck
make clang-format
make clang-tidy
```

## Generate code coverage report

1. Make sure to enable the `CODE_COVERAGE` option in the CMake configuration.
2. Compile the tests
```bash
cd build && cmake -DCODE_COVERAGE=ON -DCMAKE_BUILD_TYPE=Debug .. && make check
```
3. Generate the coverage report:
```bash
make coverage
```

**Note:** In order to generate the coverage reports, you will need `lcov`, along with `genhtml` and `xdg-open`.

## References and useful links

- **BabyZoe:** https://github.com/zcash-hackworks/babyzoe
- **Miximus:** https://github.com/barryWhiteHat/miximus.git
- **SCIPR LAB github:** https://github.com/scipr-lab/
- **Zcash github:** https://github.com/zcash/zcash
- **ZeroCash:** http://zerocash-project.org/
- **Zerocash-Ethereum:** https://github.com/AntoineRondelet/zerocash-ethereum

## License notices:

### Zcash

```
Copyright (c) 2016-2018 The Zcash developers
Copyright (c) 2009-2018 The Bitcoin Core developers
Copyright (c) 2009-2018 Bitcoin Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.


The MIT software license (http://www.opensource.org/licenses/mit-license.php)
above applies to the code directly included in this source distribution.
Dependencies downloaded as part of the build process may be covered by other
open-source licenses. For further details see 'contrib/debian/copyright'.


This product includes software developed by the OpenSSL Project for use in the
OpenSSL Toolkit (https://www.openssl.org/). This product includes cryptographic
software written by Eric Young (eay@cryptsoft.com).


Although almost all of the Zcash code is licensed under "permissive" open source
licenses, users and distributors should note that when built using the default
build options, Zcash depends on Oracle Berkeley DB 6.2.x, which is licensed
under the GNU Affero General Public License.
```

### Libsnark

```
The libsnark library is developed by SCIPR Lab (http://scipr-lab.org)
and contributors.

Copyright (c) 2012-2014 SCIPR Lab and contributors (see AUTHORS file).

All files, with the exceptions below, are released under the MIT License:

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

### Miximus

[barryWhiteHat/miximus GNU General Public License v3.0](https://github.com/barryWhiteHat/miximus/blob/master/LICENSE)
