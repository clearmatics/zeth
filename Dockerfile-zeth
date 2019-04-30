FROM clearmatics/zeth-base

# Copy the project in the docker container
COPY . /home/zeth

# Install the submodules
RUN cd /home/zeth && git submodule update --init --recursive

WORKDIR /home/zeth

CMD ["/bin/bash"]
