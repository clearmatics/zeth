#!/usr/bin/env bash

###########################################################################################
# This file contains a basic agent that deploys a new Zeth instance, and generates       #
# a batch of transactions. This is useful to generate Zeth transactions datasets quickly. #
###########################################################################################

# Singleton Deterministic agent.
# Strategy:
# - Operates on a fresh Zeth deployment
# - Create initial Zeth notes by depositing ETH to the Mixer
# - Carry out a fixed number of Zeth "payments-to-self"

set -e
set -x

if [ "$#" -ne 3 ] || [ "$1" == "" ] || [ "$2" = "" ] || [ "" == "$3" ] ; then
   echo "error: invalid arguments"
   echo "Usage: $0 <eth-network> <agent-name> <transaction-number>"
   echo "E.g. $0 ganache agent_0 10"
   exit 1
fi

echo "== RUNNING ON NETWORK: $1 =="
eth_network=$1
echo "== AGENT NAME: $2 =="
agent=$2
echo "== AGENT EMITTING: $3 TRANSACTIONS =="
tx_number=$3

# Bring util functions to the scope
. ../test_zeth_cli_common.sh

# Folder containing the simulation results
BASE_DIR=$ZETH/_singleton_simulation_results
# Folder of the contract deployer
DEPLOYER_DIR=${BASE_DIR}/deployer
# Folder of the deterministic agent `user`
USER_DIR=${BASE_DIR}/user

# Setup users' wallets
mkdir -p ${BASE_DIR}
pushd ${BASE_DIR}

echo "[INFO] System users setup..."
# `setup_user_local_key` creates an Ethereum and Zeth
# keypair for the users, and funds their Ethereum accounts.
setup_user_local_key deployer ${eth_network}
setup_user_local_key user ${eth_network}

# Deploy the contracts and distribute the deployment details (instance file)
! [ -e deployer/zeth-instance ] && \
    run_as deployer zeth deploy
copy_deployment_info deployer user

# Filename where the IDs of each tx emitted by the users are stored
# This file can be consumed line-by-line to inspect all transactions
# via `web3.eth.getTransaction()` and `web3.eth.getTransactionReceipt()`
TXIDS_FILE=txids.txt

echo "============================================================"
echo "==                   Start Simulation                     =="
echo "============================================================"

echo "Balances at the beggining of the simulation"
show_balances user

# User deposits 10000 and does $tx_number payments to self
pushd user
user_pk=`cat zeth-address.pub`
if ! [ -e notes/state_zeth ] ; then
    zeth mix --wait --vin 10000 --out ${user_pk},10000
fi

if [ ! -f "$TXIDS_FILE" ]; then
    echo "$TXIDS_FILE does not exist in the user's folder. Creating it..."
    touch $TXIDS_FILE
fi

for i in $( seq 0 $tx_number )
do
    note_id=`zeth ls-notes | tail -n 1 | grep -oe '^[A-Za-z0-9]\+'`
    ! [ "" == ${note_id} ]

    tx_id=`zeth mix --wait --in ${note_id} --out ${user_pk},100 | head -n 4 | tail -n 1`
    # Log the transaction ID to allow the python script to consume the transaction IDs
    echo "$tx_id" >> "$TXIDS_FILE"
    
    # Sync and check that our note has been spent
    zeth sync
    if (zeth ls-notes | grep ${note_id}) ; then
        echo Expected note ${note_id} to be marked spent
        exit 1
    fi
done

popd # user

echo "Balances at the end of the simulation"
show_balances user

popd # BASE_DIR

set +x
set +e

echo "============================================================"
echo "==                    End Simulation                      =="
echo "============================================================"
