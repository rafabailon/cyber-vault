.PHONY: run test coverage clean

PYTHON ?= python3

run:
	PYTHONPATH=src $(PYTHON) src/cyber_vault.py

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

coverage:
	PYTHONPATH=src $(PYTHON) -m trace --count --summary --coverdir=coverage-report --ignore-dir=/usr --module unittest discover -s tests

clean:
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -type f -name '*.py[co]' -delete
	rm -rf coverage-report .coverage build dist *.egg-info .pytest_cache
