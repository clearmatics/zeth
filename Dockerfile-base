FROM ubuntu:19.04

####
# This Dockerfile builds the base image (installs all the dependencies) for Zeth
####

# Install necessary packages
RUN apt-get update && apt-get install -y \
        git \
        libboost-all-dev \
        libgmp3-dev \
        libprocps-dev \
        g++ \
        gcc \
        libxslt-dev \
        vim \
        cmake \
        libssl-dev \
        pkg-config \
        curl \
        sudo

# Configue the environment for gRPC
RUN apt-get install -y \
        build-essential \
        autoconf \
        libtool
RUN git clone -b v1.24.x https://github.com/grpc/grpc /var/local/git/grpc
RUN cd /var/local/git/grpc && git submodule update --init --recursive
RUN cd /var/local/git/grpc/third_party/protobuf && ./autogen.sh && ./configure --prefix=/usr && make -j12 && make check && make install && make clean
RUN cd /var/local/git/grpc && make install

CMD ["/bin/bash"]
