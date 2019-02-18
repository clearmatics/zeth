# Python client to interact with the prover

## Versions

- Python 3

## Run the client

1. Generate the stub code:
```bash
# Install grpcio-tools
pip3 install grpcio-tools

# Generate the stub code
python -m grpc_tools.protoc -I../api/ --python_out=. --grpc_python_out=. ../api/prover.proto
```
