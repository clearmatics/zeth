
.PHONY: setup check test syntax grpc

setup:
	pip install --upgrade pip
	pip install .
	$(MAKE) grpc

setup-dev dev:
	pip install --upgrade pip
	pip install -e .
	$(MAKE) grpc
	@echo "************** INSTALLED FOR DEVELOPMENT **************"

check: syntax test

PROTOBUF_OUTPUT := \
  api/prover_pb2.py api/prover_pb2_grpc.py \
  api/pghr13_messages_pb2.py api/pghr13_messages_pb2_grpc.py \
  api/groth16_messages_pb2.py api/groth16_messages_pb2_grpc.py \
  api/util_pb2.py api/util_pb2_grpc.py

api/%_pb2.py api/%_pb2_grpc.py: ../api/%.proto
	python -m grpc_tools.protoc \
      -I.. --proto_path .. --python_out=. --grpc_python_out=. api/$*.proto

grpc: $(PROTOBUF_OUTPUT)
	@# suppress "Nothing to do for ..." warning
	@echo -n

syntax: ${PROTOBUF_OUTPUT}
	flake8 `git ls-files 'zeth/**.py' 'test/**.py'`
	mypy `git ls-files 'test/**.py' 'test_commands/**.py' 'zeth/**.py'`

test: ${PROTOBUF_OUTPUT}
	python -m unittest
