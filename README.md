# Zeth - Zerocash on Ethereum 

**Disclaimer:** This work is heavily inspired from [babyzoe](https://github.com/zcash-hackworks/babyzoe), [Miximus](https://github.com/barryWhiteHat/miximus.git), and follows the design presented in [zerocash-ethereum](https://github.com/AntoineRondelet/zerocash-ethereum).

:point_right: Check our documentation on the [paper](https://gitlab.clearmatics.net/ar/zeth-protocol/blob/master/zeth.pdf) to have more details about Zeth.

## Building the project:

### Using docker (Recommended)

In order to run the project, you will need 3 terminals. 
One termonal will run the proving service/server, another one will run the ethereum testnet, and the final one
will run the solidity tests.
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

# Generate an address and a "dummy" coin
python src/py-utils/address_generator/main.py
python src/py-utils/coin_generator/main.py

# Compile the circuit
mkdir build
cd build
cmake .. && make

# Start the proving server
make
./src/prover_server
```

#### Terminal 2: Start an Ethereum testnet to test the smart contracts

```bash
# Start the ethereum test net by running the following commands
cd zeth-contracts
npm run testrpc
```

#### Terminal 3: Start the solidity tests

```bash
# We assume here that you are in /home/zeth
cd zeth-contracts
npm install

# Run a trusted setup for the tests
zeth setup

# Run the tests
truffle test
```

### Without docker

#### Configure your environment

```bash
# Install dependencies
sudo apt-get install libboost-all-dev
sudo apt-get install libgmp3-dev
sudo apt-get install libprocps-dev

node --version # v10.15.0
npm --version # 6.4.1
truffle --version # v5.0.1
ganache-cli --version # v6.2.5

# Setup your environment
. ./setup_env.sh

# Make sure you have python 3 installed
# and that you have pycrypto (pip install pycrypto)
```

#### Create an address pair

```bash
python src/py-utils/address_generator/main.py
```

#### Create a coin

```bash
python src/py-utils/coin_generator/main.py
```

#### Build libsnark gadget to generate verification key and proving key

##### Get dependencies

```bash
git submodule update --init --recursive
```

##### Create the build repo and build the project

```bash
mkdir build
cd build
cmake .. && make
cd .. && ./build/src/main
```

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

### Use the CLI

These commands are ran in the `zeth` repo.

```bash
# Generate the trusted setup (proving and verification keys)
zeth setup

# Generate a proof for a given commitment in the tree
zeth prove [Args] # See Usage of the command
```

### Launch the Python wrapper

```
cd pythonWrapper
python __main__.py
```

**Note:** The Python wrapper is WIP, and tries to simulate the flow of transactions: Alice -> Bob (Alice deposit for Bob to withdraw), Bob -> Charlie (Bob decides to use the commitment he "controls" to deposit a new one for Charlie), Charlies withdraws.
I have a bunch of errors with the `forward` function, that I need to fix: See: https://github.com/AntoineRondelet/snark-mixer/issues/2

### Launch the Javascript wrapper

```
cd jsWrapper
npm install
node deployDepositWithdraw.js
```

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
