# SNARK on Ethereum - PoC (Adapated from [Miximus](https://github.com/barryWhiteHat/miximus.git))

## How it works

We imagine a scenario where Alice does a deposit to the Mixer, sends the secret infrmation to Bob (off-chain or however she likes as long as it is kept secret between Bob and her), and Bob withdraws the ether previously deposited by Alice.

1. Alice pays `1 ether` (fixed denomination for now) when calling the `deposit()` function in `miximus.sol`. Thus, she gets the right to append single leaf in the merkle tree.
2. Alice sends the secret data to Bob
3. Bob can withdraw 1 ether from the contract if has the secret key (`sk`) and `nullifier` of the leaf created by Alice. However, rather than revealing the secret information to the network (and especially to the verifier) to prove that he "control" the leaf creqted by Qlice (by "control" we mean: "Knows the secret data corresponding to the leaf created by Alice"), he generates a zero-knowledge proof (zk-SNARK proof here) of knowledge of the secret.
That way, Bob is able to prove to the verifier that he knows the secret associated with Alice's leaf in the tree, without revealing it. Moreover, Bob also creates a proof that the leaf he provides a proof of knowledge of the associated secret is indeed in the merkle tree. In fact, Bob knows that he provides a proof of knowledge of the secret associated with the leaf created by Alice, BUT, he does not want to leak the link between Alice and him to the rest of the network.
4. The verification process of the proof provided by Bob, reveals the `nullifier`, but not the `sk` (secret data). Thus, no one is in position to tell which `nullifier` maps to which leaf. Furthermore, to prevent double spends the smart contract tracks the `nullifiers` and only allows a single withdrawal per `nullifier`. 

## Building the project:

### Build libsnark gadget to generate verificaction key and proving key

1. Get dependencies:
```bash
git submodule update --init --recursive
```
2. Create the build repo and build the project:
```bash
mkdir build
cd build
cmake .. && make
cd ../zksnark_element && ../build/src/main
```

**Note:**
In order to compile the project on macOS (see: https://github.com/scipr-lab/libsnark/issues/99), run:
```bash
brew install pkg-config

mkdir build && cd build

LD_LIBRARY_PATH=/usr/local/opt/openssl/lib:"${LD_LIBRARY_PATH}"
CPATH=/usr/local/opt/openssl/include:"${CPATH}"
PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig:"${PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH CPATH PKG_CONFIG_PATH

CPPFLAGS=-I/usr/local/opt/openssl/include LDFLAGS=-L/usr/local/opt/openssl/lib PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig cmake -DWITH_PROCPS=OFF -DWITH_SUPERCOP=OFF ..

make

cd ../zksnark_element && ../build/src/main
```

### Deploy and run the tests

Deploy the contract and perform a single mixing transaction from address `0xffcf8fdee72ac11b5c542428b35eef5769c409f0` to `0x3fdc3192693e28ff6aee95320075e4c26be03308`:
```bash
cd snarkWrapper
npm install
testrpc -d
node deploy.js
```

## References

- **BabyZoe:** https://github.com/zcash-hackworks/babyzoe
- **Hackishlibsnarkbindings:** https://github.com/ebfull/hackishlibsnarkbindings
- **Miximus:** https://github.com/barryWhiteHat/miximus.git
