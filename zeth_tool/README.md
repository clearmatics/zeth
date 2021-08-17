# `zeth-tool`

Primarily designed for performing fine-grained operations, either outside of the scope of the zeth client, or as part of larger high-level operations.

Examples include, generation of arbitrary proofs (given a proving key and full assignment), verification of arbitrary proofs (given a proof, verification key and primary input), re-serialization of objects (e.g. conversion to/from binary, JSON etc).

Since the tool is more development / administration focussed, not all functionality is necessarily complete, and may be extended as required in the future (possibly including operations that are specific to the zeth circuit).

To build, run `make zeth-tool` in the `build` directory (see the [main README](../README.md)) to build to executable at `build/zeth_tool/zeth-tool`. Run `zeth-tool help` (with the appropriate path to the executable) to see the up-to-date list of supported commands.
