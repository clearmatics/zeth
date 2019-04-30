FROM python:3.6.8-slim-jessie

####
# This Dockerfile builds the base image (installs all the dependencies) for Zeth
####

RUN apt-get update && apt-get install -y \
        git \
        libboost-all-dev \
        libgmp3-dev \
        libprocps-dev \
        g++ \
        gcc \
        libxslt-dev \
        vim \
        libssl-dev \
        pkg-config \
        curl \
        sudo

# Install a recent version of nodejs
RUN curl -sL https://deb.nodesource.com/setup_10.x | sudo bash - && sudo apt-get install -y nodejs

# Configure the environment for gRPC
RUN apt-get install -y \
        build-essential \
        autoconf \
        libtool

# Install the last version of cmake
RUN pip install cmake --upgrade

RUN git clone -b v1.20.x https://github.com/grpc/grpc /var/local/git/grpc
RUN cd /var/local/git/grpc && git submodule update --init --recursive
RUN cd /var/local/git/grpc/third_party/protobuf && ./autogen.sh && ./configure --prefix=/usr && make -j12 && make check && make install && make clean
RUN cd /var/local/git/grpc && make install

CMD ["/bin/bash"]
