#!/usr/bin/env bash

set -e

COORDINATOR_HOST_ENTRY="${COORDINATOR_IP} mpc-coordinator"
echo ${COORDINATOR_HOST_ENTRY} >> /etc/hosts

echo "Phase1 binaries >> $(which compute)"
echo "Phase2 binaries >> $(which mpc-client-phase2)"

exec "$@"
