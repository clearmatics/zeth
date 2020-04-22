
.PHONY: setup setup-dev dev check test syntax grpc test_contracts

setup:
	pip install --upgrade pip --progress-bar off
	pip install -e . --progress-bar off
	$(MAKE) grpc
	python -c "from zeth.contracts import install_sol; \
		install_sol()"

check: syntax test

PROTOBUF_OUTPUT := \
  api/prover_pb2.py api/prover_pb2_grpc.py \
  api/pghr13_messages_pb2.py api/pghr13_messages_pb2_grpc.py \
  api/groth16_messages_pb2.py api/groth16_messages_pb2_grpc.py \
  api/ec_group_messages_pb2.py api/ec_group_messages_pb2_grpc.py \
  api/snark_messages_pb2.py api/snark_messages_pb2_grpc.py \
  api/zeth_messages_pb2.py api/zeth_messages_pb2_grpc.py

api/%_pb2.py api/%_pb2_grpc.py: ../api/%.proto
	python -m grpc_tools.protoc \
      -I.. --proto_path .. --python_out=. --grpc_python_out=. --mypy_out=. \
      api/$*.proto

grpc: $(PROTOBUF_OUTPUT)
	@# suppress "Nothing to do for ..." warning
	@echo -n

syntax: ${PROTOBUF_OUTPUT}
	flake8 `git ls-files '**.py'`
	mypy -p api
	mypy -p zeth
	mypy -p test
	mypy -p test_commands
	mypy -p commands
	pylint zeth test test_commands commands

test: ${PROTOBUF_OUTPUT}
	python -m unittest

test_contracts: ${PROTOBUF_OUTPUT}
	python test/test_contract_base_mixer.py
