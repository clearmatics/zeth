# Utility functions for general build tasks.
#
# All functions expect to be executed the root directory of the repository, and
# will exit with this as the current directory.


# Init some global variables related to the platform. Some other functions may
# expect this to be called before they are invoked.
function init_platform() {
    platform=`uname`
    echo platform=${platform}
}

# Assert that init_platform has been called
function assert_init_platform() {
    if [ "${platform}" == "" ] ; then
        echo init_platform has not been called
        exit 1
    fi
}

# Install dependencies for cpp builds
function cpp_build_setup() {
    assert_init_platform

    # Extra deps for native builds

    if [ "${platform}" == "Linux" ] ; then
        if (which apk) ; then
            # Packages already available in Docker build
            echo -n             # null op required for syntax
        elif (which yum) ; then
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y \
                 openssl openssl-devel \
                 gmp-devel procps-devel cmake3 \
                 python3 python3-devel \
                 boost-devel
        else
            sudo apt install \
                 libboost-dev \
                 libboost-system-dev \
                 libboost-filesystem-dev \
                 libboost-program-options-dev \
                 libgmp-dev \
                 libprocps-dev \
                 libxslt1-dev \
                 pkg-config
        fi
    fi
}
