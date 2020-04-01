#!/bin/bash

export ZETH=`pwd`
export ZETH_CONTRACTS_DIR=$ZETH/zeth-contracts/contracts
export ZETH_DEBUG_DIR=$ZETH/debug

mkdir -p $ZETH/coinstore
export ZETH_COINSTORE=$ZETH/coinstore

mkdir -p $ZETH/trusted_setup
export ZETH_TRUSTED_SETUP_DIR=$ZETH/trusted_setup

# Add the zeth executables in the PATH
export PATH=$ZETH/build/prover_server:$ZETH/build/mpc_tools:$ZETH/build/mpc_tools/mpc_phase2:$PATH
