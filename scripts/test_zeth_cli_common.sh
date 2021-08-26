
TRUFFLE_DIR=`pwd`/zeth_contracts

function run_truffle() {
    pushd ${TRUFFLE_DIR}
    eval truffle $@
    popd
}

function run_as() {
    pushd $1
    shift
    eval $@
    popd
}

function show_balances() {
    run_truffle exec ../scripts/test_zeth_cli_show_balances.js
}

# Show the balance for the users in the test, based on their locally managed
# accounts.
function show_balances() {
    for name in deployer alice bob charlie ; do
        pushd ${name}
        echo -n "${name}: "
        zeth-helper eth-get-balance
        popd
    done
}

# 1 - name
function setup_user_hosted_key() {
    mkdir -p $1
    pushd $1
    ! [ -e eth-network ] && \
        (zeth-helper eth-gen-network-config)
    ! [ -e eth-address ] && \
        (grep $1 ../accounts | grep -oe '0x.*' > eth-address)
    ! [ -e zeth-address.priv ] && \
        (zeth gen-address)
    popd
}

# 1 - name
# 2 - (optional) network-name
function setup_user_local_key() {
    mkdir -p $1
    pushd $1
    ! [ -e eth-network ] && \
        (zeth-helper eth-gen-network-config $2)
    ! [ -e eth-address ] && \
        (zeth-helper eth-gen-address && zeth-helper eth-fund)
    ! [ -e zeth-address.priv ] && \
        (zeth gen-address)

    # Ensure that we have been able to perform all of these operations without
    # querying the prover-server for the configuration.
    if [ -e prover-config.cache ] ; then
        echo Expected no prover config file
        exit 1
    fi

    popd
}

# 1 - deployer_name
# 2 - user_name
function copy_deployment_info() {
    cp $1/zeth-instance $2
}
