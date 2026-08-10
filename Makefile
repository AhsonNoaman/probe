# Everything a fresh clone needs, in the order you would need it.
.PHONY: help install search experiment report test check clean-runs

PY := .venv/bin/python
FLIGHTOPS ?= ../flight-ops-deployment

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n", $$1, $$2}'

install:  ## create the venv, install probe and the flightops checkout it targets
	python3 -m venv .venv
	$(PY) -m pip install -q -e '.[dev]'
	$(PY) -m pip install -q -e $(FLIGHTOPS)

search:  ## one offline search against the reference agent; no API key, no cost
	$(PY) scripts/run_search.py --target reference --ledger search --milestone m3

experiment:  ## the whole measurement: search, defences, utility, held-out gap
	$(PY) scripts/run_experiment.py
	$(PY) scripts/build_report.py

report:  ## regenerate the static findings report from the committed run logs
	$(PY) scripts/build_report.py

test:  ## the whole suite, offline
	$(PY) -m pytest -q

check:  ## lint, types, tests
	$(PY) -m ruff format --check src tests scripts
	$(PY) -m ruff check src tests scripts
	$(PY) -m mypy
	$(PY) -m pytest -q

clean-runs:  ## drop ad-hoc run output; committed runs are tracked and survive
	git clean -fd data/runs
	rm -f data/reference.duckdb
