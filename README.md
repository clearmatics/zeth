# Zeth - Zerocash on Ethereum 

**Disclaimer:** Adapated from [Miximus](https://github.com/barryWhiteHat/miximus.git), and following the design
presented in [zerocash-ethereum](https://github.com/AntoineRondelet/zerocash-ethereum).

## Building the project:

### Using docker

```
# Clone this repository:
git clone git@gitlab.clearmatics.net:ar/zeth.git
cd zeth

git submodule update --init --recursive
docker build -t zeth-dev .
docker run -ti zeth-dev

# Configure your environment
. ./setup_env.sh

# Generate an address and a "dummy" coin
python src/py-utils/address_generator/main.py
python src/py-utils/coin_generator/main.py

# Compile the circuit
mkdir build
cd build
cmake .. && make

# Run the tests
make test_prover
./src/test_prover

# Test the zeth command line (see the usage)
zeth

# Run the trusted setup
zeth setup

# Generate a proof
zeth prove [args] 
```

### Without docker

#### Configure your environment

```bash
# Install dependencies
sudo apt-get install libboost-all-dev
sudo apt-get install libgmp3-dev
sudo apt-get install libprocps-dev

# Setup your environment
. ./setup_env.sh

# Make sure you have python 3 installed
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
