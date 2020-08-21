#!/bin/bash

ln -fs .dockerignore-prover .dockerignore
docker build -f Dockerfile-prover -t zeth-prover-img .
