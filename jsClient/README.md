# NodeJS client to interact with the prover

This folder contains some util functions and mock data to interact with the prover RPC service.

**WARNING:** The `getProof.js` file needs to be adapted depending on the JoinSplit description used on the prover side. Here it assumes that the circuit takes 1 input and 1 output.

## Fetch the verification key

```
node getVerificationKey.js
```

## Get a proof on given inputs

```
node getProof.js
```
