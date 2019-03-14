# Python client to interact with the prover

## Environment

We assume that Python3 is installed, along with the [venv](https://docs.python.org/3/library/venv.html#module-venv) module.

```
$ python --version
Python 3.6.3
```

## Run the client

### Create a virtual environment

```
python -m venv zeth-devenv
source zeth-devenv/bin/activate
```

### Install the dependencies

```
pip install -r requirements.txt
```

### Generate the stub code:

```
# Generate the stub code
python -m grpc_tools.protoc -I../api/ --python_out=. --grpc_python_out=. ../api/prover.proto
```

### Start the testing client

```
python testStub.py #to test ethereum mixing
python testStubToken.py #to test token mixing
```
