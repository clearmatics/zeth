
.PHONY: setup setup-dev dev check test syntax grpc test_contracts

setup:
	pip install --upgrade pip --progress-bar off
	pip install -e . --progress-bar off
	$(MAKE) grpc
	python -c "from zeth.core.contracts import install_sol; \
		install_sol()"

check: syntax test

PROTOBUF_OUTPUT := \
  zeth/api/prover_pb2.py zeth/api/prover_pb2_grpc.py \
  zeth/api/pghr13_messages_pb2.py zeth/api/pghr13_messages_pb2_grpc.py \
  zeth/api/groth16_messages_pb2.py zeth/api/groth16_messages_pb2_grpc.py \
  zeth/api/ec_group_messages_pb2.py zeth/api/ec_group_messages_pb2_grpc.py \
  zeth/api/snark_messages_pb2.py zeth/api/snark_messages_pb2_grpc.py \
  zeth/api/zeth_messages_pb2.py zeth/api/zeth_messages_pb2_grpc.py

zeth/api/%_pb2.py zeth/api/%_pb2_grpc.py: ../proto/zeth/api/%.proto
	python -m grpc_tools.protoc \
      -I../proto --proto_path ../proto --python_out=. --grpc_python_out=. --mypy_out=. \
      zeth/api/$*.proto

grpc: $(PROTOBUF_OUTPUT)
	@# suppress "Nothing to do for ..." warning
	@echo -n

syntax: ${PROTOBUF_OUTPUT}
	flake8 `git ls-files '**.py'`
	mypy -p zeth
	mypy -p test_commands
	mypy -p zeth_misc
	pylint zeth.core zeth.cli zeth.test test_commands zeth_misc

test: ${PROTOBUF_OUTPUT}
	python -m unittest

test_contracts: ${PROTOBUF_OUTPUT}
	python test_commands/test_contract_base_mixer.py
	python test_commands/test_merkle_tree_contract.py
