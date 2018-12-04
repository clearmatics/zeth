# ZkSNARK on Ethereum - PoC (Adapated from [Miximus](https://github.com/barryWhiteHat/miximus.git))

## How it works - High level description

We imagine a scenario where Alice and Bob agreed on doing a private Tx of 1ether (from Alice to Bob).
In order to do so, Alice does a deposit to the Mixer, sends the secret information (that enables to compute the commitment she added in the merkle tree of the mixer) to Bob, and Bob withdraws the ether previously deposited by Alice.
By doing so, Alice and Bob never interact directly with one another, and Bob provides a zero knowledge proof of knowledge of the secret we he withdraw his funds. That way, he does not leak which "commitment" in the tree he is withdrawing for, and thus, no one should be able to know that his withdraw is for the commitment added by Alice.
The link Alice - Bob, is protected by the proof Bob generates.

When Alice wants to send 1ether to Bob, here is what happens:
1. Alice pays `1 ether` (fixed denomination for now) when calling the `deposit()` function in `Miximus.sol`. Thus, she gets the "right" to append single leaf in the merkle tree. This leaf is computed from Bob's address along with a salt and a secret. That way, only the parties who know these pieces of data can recompute the commitment.
2. Alice sends the secret data to Bob
3. Bob can withdraw 1ether from the contract if has the secret key (`sk`) and `nullifier` of the leaf created by Alice. However, rather than revealing the secret information to the network (and especially to the verifier) to prove that he "controls" the leaf created by Alice (by "control" we mean: "Knows the secret data corresponding to the leaf created by Alice"), he generates a zero-knowledge proof of knowledge of the secret, that basically says: "I know the secret that enables to compute one commitment that is in the merkle tree of root R, and which has not been used to carry out a withdraw up to now".
That way, Bob is able to prove to the verifier that he knows the secret associated with Alice's leaf in the tree, without revealing it. Moreover, Bob also creates a proof that the leaf he provides a proof of knowledge of the associated secret is indeed in the merkle tree. In fact, Bob knows that he provides a proof of knowledge of the secret associated with the leaf created by Alice, BUT, he does not want to leak the link between Alice and him to the rest of the network.
4. The verification process of the proof provided by Bob, reveals the `nullifier`, but not the `sk` (secret data). Thus, no one is in position to tell which `nullifier` maps to which leaf. Furthermore, to prevent double spends the smart contract tracks the `nullifiers` and only allows a single withdrawal per `nullifier`. 

## Notes

The terms "unspent commitment" refer to a commitment in the Merkle Tree of the mixer for which the nullifier **has not been** revealed yet.
Same applies for "spent commitment", which refers to a commitment in the Merkle Tree of the mixer for which the nullifier **has been** revealed.

**Note:** That this knowledge is onyl accessible by the "owner" of the commitment. No one in the network can know whether one commitment has been spent or not, if they were not the intended recipient of the transaction that created the commitment.

1. We see that Alice needs to "burn" 1ether from her public balance in order to append a commitment in the Mixer. This leaks the fact that Alice is doing a payment through the Mixer.
2. If the Merkle tree containing the commitments is empty, and if Alice appends a commitment, sends the secrets to Bob, and Bob withdraw his 1ether, then the payment is not private at all. We see, that the more people use the Mixer, the bigger the anonymity set, and then the better the level of privacy.
3. If Bob "receives Alice's payment" (he can withdraw from the tree), but would like to pay someone through the Mixer **without** depositing one ether; he can *"forward"* Alice's payment to someone else. By doing so, he needs to provide a proof (like a normal withdrawal), but also, a new commitment to insert in the tree. Instead, of being credited of 1ether, the proof is verified, and the new commitment is appended to the tree **ONLY IF** the proof is valid. He has now "spent" his commitment (the corresponding nullifier has been revealed), in order to append a new leaf in the Merkle Tree.
4. If Alice shares the secret with Bob is a careless manner, she can leak the link she has with Bob to the rest of the network. To do so, we can use a "TransactionRelay/Broadcaster" contract, to break the link between Alice and Bob, and do an encrypted broadcast that only Bob could decrypt. This is described with more details here: https://github.com/AntoineRondelet/snark-mixer/issues/5 and here: https://github.com/AntoineRondelet/blockchain-privacy
5. Since the nullifier is computed with the recipient's address, an additional check in the Mixer (see withdraw function), allow to make sure the person trying to withdraw the 1ether is indeed the recipient, and not a malicious sender. While, the sender knows all the data to compute the commitment, he cannot claim the 1ether back because he needs to call the withdraw function with the address of the recipient.

## Building the project:

### Configure your environment

```bash
. ./setup_env.sh
```

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

```bash
cd ../zksnark_element

# Generate the trusted setup (proving and verification keys)
../build/src/main setup

# Generate a proof for a given commitment in the tree
../build/src/main prove [Args] # See Usage of the command
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
