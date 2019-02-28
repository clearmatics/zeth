# Zeth - Zerocash on Ethereum 

:rotating_light: **WARNING** This project is a Proof of Concept. It is highly inefficient and has not be thoroughly reviewed. Please do not use in production!

**Disclaimer:** This work is inspired from [babyzoe](https://github.com/zcash-hackworks/babyzoe), [Miximus](https://github.com/barryWhiteHat/miximus.git). 
It follows and extend the design presented in [zerocash-ethereum](https://github.com/AntoineRondelet/zerocash-ethereum) by adapting some code initially written by ZCash.

:point_right: Check our [paper](https://gitlab.clearmatics.net/ar/zeth-protocol/blob/master/zeth.pdf) for more information about ZETH.

## Building the project:

### Using docker (Recommended)

In order to run the project, you will need 3 terminals.
One terminal will run the proving service/server, another one will run the ethereum testnet, and the final one
will run a python stub that triggers a few proof generations on the proving server in order to do confidential transactions on the Ethereum testnet.

The titles of the sections below are prefixed with the terminal ID the commands should be ran into.

#### Terminal 1: Configure the project and run the cpp tests (Docker)

```bash
# Clone this repository:
git clone git@gitlab.clearmatics.net:ar/zeth.git
cd zeth
git submodule update --init --recursive

docker build -t zeth-dev .
docker run -ti -p 50051:50051 --name zeth zeth-dev

## All the commands below are ran in the docker container
# Configure your environment
. ./setup_env.sh

# Compile the circuit
mkdir build
cd build
cmake ..

# Run the tests (optional)
make check # Builds and run the tests (once the tests are built once, calling "make test" suffices to execute them)

# Compile and start the proving server
make
./src/prover_server
```

#### Terminal 2: Start an Ethereum testnet to test the smart contracts

```bash
# Start the ethereum test net by running the following commands
cd zeth-contracts
npm run testrpc
```

#### Terminal 3: Start the testing Python stub

```bash
cd pyClient

# Follow the few steps described in the README of the python stub
```

### Without docker

#### Configure your environment

```bash
# Install dependencies
sudo apt-get install libboost-all-dev
sudo apt-get install libgmp3-dev
sudo apt-get install libprocps-dev

# Make sure you have gRPC installed (see: https://github.com/grpc/grpc/blob/v1.19.0/src/cpp/README.md)

node --version # v10.15.0
npm --version # 6.4.1
truffle --version # v5.0.1
ganache-cli --version # v6.2.5
protoc --version # libprotoc 3.6.1

# Setup your environment
. ./setup_env.sh
```

#### Run the prover

Follow the steps described in the Docker section (install submodules, compile, test and run)

**Note:**
In order to compile the project on **MacOS** (see: https://github.com/scipr-lab/libsnark/issues/99), run:

```bash
brew install pkg-config

mkdir build && cd build

LD_LIBRARY_PATH=/usr/local/opt/openssl/lib:"${LD_LIBRARY_PATH}"
CPATH=/usr/local/opt/openssl/include:"${CPATH}"
PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig:"${PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH CPATH PKG_CONFIG_PATH

CPPFLAGS=-I/usr/local/opt/openssl/include LDFLAGS=-L/usr/local/opt/openssl/lib PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig cmake -DWITH_PROCPS=OFF -DWITH_SUPERCOP=OFF ..

make
```

### Use the pyClient or the jsClient

This Proof of Concept comes with the building blocks to integrate zeth into your DApp.
You can use the python and/or the javascript clients to interact with the proving service and request proofs on a given input.
This is a great way to experiment with confidential asset transfer on Ethereum!

If you do not know where to start, don't panic! Just follow the instructions of the README in `pyClient` to run the `testStub.py` script.
This script implements a scenario where Alice, Bob and Charlie do confidential asset transfers.

**Note:** These clients are very minimal and only used for testing purpose.
We provide the building block to write a CLI or a frontend to make ZETH more user friendly, and we welcome any contributions! :)

## References

- **BabyZoe:** https://github.com/zcash-hackworks/babyzoe
- **Hackishlibsnarkbindings:** https://github.com/ebfull/hackishlibsnarkbindings
- **Miximus:** https://github.com/barryWhiteHat/miximus.git
- **ZeroCash:** http://zerocash-project.org/
- **ZCash github:** https://github.com/zcash/zcash
- **SCIPR LAB github:** https://github.com/scipr-lab/
- **Zerocash-Ethereum:** https://github.com/AntoineRondelet/zerocash-ethereum

## License notices:

### ZCash

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
