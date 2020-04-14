
TRUFFLE_DIR=`pwd`/zeth-contracts

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

function show_balances_named() {
    run_truffle exec ../scripts/test_zeth_cli_show_balances_named.js
}

function new_account() {
    run_truffle exec ../scripts/test_zeth_cli_new_account.js | grep -e '^0x.*'
}

# 1 - Address to show balance for
function show_balance() {
    python -m test_commands.get_balance $1
}

# Record all Ethereum accounts in an 'accounts'
function get_accounts() {
    if ! [ -e accounts ] ; then
        run_truffle exec ../scripts/test_zeth_cli_get_accounts.js > accounts
    fi
}

# 1 - name
function setup_user() {
    mkdir -p $1
    pushd $1
    ! [ -e eth-address ] && \
        (grep $1 ../accounts | grep -oe '0x.*' > eth-address)
    ! [ -e zeth-address.json ] && \
        (zeth gen-address)
    popd
}

# 1 - deployer_name
# 2 - user_name
function copy_deployment_info() {
    cp $1/zeth-instance.json $2
}
