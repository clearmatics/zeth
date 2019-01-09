FROM python:3.6.7-slim-jessie

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

COPY . /home/zeth

#RUN cd zeth-contracts && npm install

RUN pip install pycrypto

WORKDIR /home/zeth

CMD ["/bin/bash"]
