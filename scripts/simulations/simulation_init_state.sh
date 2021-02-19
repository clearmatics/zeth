#!/usr/bin/env bash

set -e
set -x

# Bring the simulation configuration config to scope
. ./simulation_config.sh
# Bring the util functions to scope
. ../test_zeth_cli_common.sh

# Directory that contains the initial state of the simulation
BASE_DIR=$ZETH/_simulation_init
mkdir -p ${BASE_DIR}
pushd ${BASE_DIR}

# 1. Deploy the contracts on the network
## Setup the deployer's environment
setup_user_local_key deployer ${CONFIG_ETH_NETWORK}
## Deploy the contracts
! [ -e deployer/zeth-instance ] && \
    run_as deployer zeth deploy

# 2. Init all agents state, and
# 3. Build public initial state (public keystore)
# i.e. aggregate all Zeth public keys in a single keystore folder
mkdir -p keystore
for i in $( seq 0 $CONFIG_AGENTS_NUMBER )
do
    agent_name="agent_$i"
    setup_user_local_key ${agent_name} ${CONFIG_ETH_NETWORK}
    copy_deployment_info deployer ${agent_name}
    # Build the keystore of public keys
    cp ${agent_name}/zeth-address.pub keystore/zeth-address_${agent_name}.pub
done

popd # BASE_DIR

set +x
set +e

echo "============================================================"
echo "==             State initialization finished              =="
echo "============================================================"
