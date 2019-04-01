FROM python:3.6.8-slim-jessie

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

# Install a recent version of nodejs
RUN curl -sL https://deb.nodesource.com/setup_10.x | sudo bash - && sudo apt-get install -y nodejs
RUN npm install -g truffle ganache-cli

# Configue the environment for gRPC
RUN apt-get install -y \
        build-essential \
        autoconf \
        libtool
RUN git clone -b $(curl -L https://grpc.io/release) https://github.com/grpc/grpc /var/local/git/grpc
RUN cd /var/local/git/grpc && git submodule update --init --recursive
RUN cd /var/local/git/grpc/third_party/protobuf && ./autogen.sh && ./configure --prefix=/usr && make -j12 && make check && make install && make clean
RUN cd /var/local/git/grpc && make install

# Copy the project in the docker container
COPY . /home/zeth

WORKDIR /home/zeth

CMD ["/bin/bash"]
