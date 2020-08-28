#!/bin/bash

export ZETH=`pwd`
export ZETH_CONTRACTS_DIR=$ZETH/zeth_contracts/contracts
export ZETH_DEBUG_DIR=$ZETH/debug

mkdir -p $ZETH/zeth_setup
export ZETH_SETUP_DIR=$ZETH/zeth_setup

# Add the zeth executables in the PATH
export PATH=$ZETH/build/prover_server:$ZETH/build/mpc_tools:$ZETH/build/mpc_tools/mpc_phase2:$PATH
