# Result of the "trusted setup"

This folder is the target to store:

- The proving key
- The verification key

**Note:** You can change the location where the result of the setup is stored, by editing the file `../setup_env.sh`

----------------

For now the trusted setup is ran by a single, trusted, entity (it is ran automatically when we start the prover server).
A more advanced piece of software would use an MPC to generate the proving and verification keys.

**Reference link:** [Zcash's power of Tau](https://z.cash.foundation/blog/conclusion-of-powers-of-tau/)
