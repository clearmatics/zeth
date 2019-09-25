
.PHONY: setup check test syntax

setup:
	pip install -e .

check: syntax test

syntax:
	flake8 `git ls-files coordinator`
	mypy -p coordinator

test:
	python -m unittest
