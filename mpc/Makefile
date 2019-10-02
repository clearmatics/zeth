
.PHONY: setup check test syntax

setup:
	pip install -e .

check: syntax test

syntax:
	flake8 `git ls-files 'coordinator/**.py' commands 'test/**.py'`
	mypy `git ls-files 'coordinator/**.py' commands 'test/**.py'`

test:
	python -m unittest
