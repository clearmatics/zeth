
.PHONY: setup check test syntax

setup:
	pip install --upgrade pip
	pip install .

setup-dev dev:
	pip install --upgrade pip
	pip install -e .
	@echo "************** INSTALLED FOR DEVELOPMENT **************"

check: syntax test

syntax:
	flake8 `git ls-files '**.py'`
	mypy `git ls-files 'test/**.py' 'test_commands/**.py' 'zeth/**.py'`

test:
	python -m unittest
