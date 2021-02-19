#!/usr/bin/env bash

##########################################################
# This file contains the generic randomized agent logic  #
##########################################################

set -e
set -x

# Bring the simulation configuration config to scope
. ./simulation_config.sh
# Bring the util functions to scope
. ../test_zeth_cli_common.sh

if ! [ "$1" == "" ] ; then
    tx_number=$1
else
    # If the number of tx is not set, we pick it randomly in {1..50}
    tx_number=$((1 + $RANDOM % 50))
fi

echo "== RUNNING ON NETWORK: $CONFIG_ETH_NETWORK =="
echo "== AGENT EMITTING: $tx_number TRANSACTIONS =="

# We assume that the agent is launched in a well-configured docker container
# one, where:
# - /home/zeth/_simulation/agent contains all the agent's keys and configuration (instance, network config etc)
# - /home/zeth/_simulation/agent/keystore contains the set of Zeth users known to the agent at the time of the simulation

BASE_DIR=$ZETH/_simulation
pushd ${BASE_DIR}

echo "============================================================"
echo "==                     Start Agent                        =="
echo "============================================================"

# User deposits funds and does $tx_number payments each of which to random receiver (the sender included)
# A simple strategy is followed for now:
# - If the agent is due to fire X transactions, then
#    - the agents deposits strcitly more than X on the contract (to avoid running out of funds), and
#    - does X transactions, each of which creating a Zeth note of value 1 (again, to make sure the agent never runs out of funds)

pushd agent
agent_pk=`cat zeth-address.pub`
if ! [ -e notes/state_zeth ] ; then
    zeth mix --wait --vin 10000 --out ${agent_pk},10000
fi

if [ ! -f "$CONFIG_TXIDS_FILE" ]; then
    echo "$CONFIG_TXIDS_FILE does not exist in the user's folder. Creating it..."
    touch $CONFIG_TXIDS_FILE
fi

for i in $( seq 0 $tx_number )
do
    note_id=`zeth ls-notes | tail -n 1 | grep -oe '^[A-Za-z0-9]\+'`
    ! [ "" == ${note_id} ]

    # Select a recipient randomly from the keystore
    recipient_id=$(($RANDOM % $(($CONFIG_AGENTS_NUMBER +1))))
    recipient_pk=`cat keystore/zeth-address_agent_${recipient_id}.pub`

    tx_id=`zeth mix --wait --in ${note_id} --out ${recipient_pk},1 | head -n 4 | tail -n 1`
    # Log the transaction ID to allow the python script to consume the transaction IDs
    echo "$tx_id" >> "$CONFIG_TXIDS_FILE"
    
    # Sync and check that our note has been spent
    zeth sync
    ##if (zeth ls-notes | grep ${note_id}) ; then
    ##    echo Expected note ${note_id} to be marked spent
    ##    exit 1
    ##fi
done

popd # agent

echo "Balances at the end of the simulation"
show_balances agent

popd # BASE_DIR

set +x
set +e

echo "============================================================"
echo "==                      Stop Agent                        =="
echo "============================================================"
