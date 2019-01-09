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
        sudo

COPY . /home/zeth

RUN pip install pycrypto

WORKDIR /home/zeth

CMD ["/bin/bash"]
