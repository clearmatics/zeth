#!/bin/bash

export ZETH=`pwd`
export ZETH_KEYSTORE=$ZETH/keystore
export ZETH_COINSTORE=$ZETH/coinstore
export ZETH_TRUSTED_SETUP_DIR=$ZETH/trusted_setup
export ZETH_DEBUG_DIR=$ZETH/debug
export ZETH_API_DIR=$ZETH/api
export ZETH_CONTRACTS_DIR=$ZETH/zeth-contracts/contracts

# Add the zeth executable in the PATH
export PATH=$ZETH/build/src:$PATH
