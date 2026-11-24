# PhishDesk developer entry points.
#
# These targets run exactly the commands documented in README.md under
# "Checks before a pull request". The README stays the written reference;
# this file exists so the same sequence is one command and cannot drift
# between the two owners' machines.
#
# Windows without GNU make: run the commands from the README directly,
# or use `make` from Git Bash / WSL.

PYTHON ?= python

.DEFAULT_GOAL := help
.PHONY: help install check lint format-check types test contracts roadmap audit

help:  ## Show the available targets
	@echo "PhishDesk targets:"
	@echo "  make install  Install pinned dev dependencies and the package"
	@echo "  make check    Run every pre-pull-request check (see README)"
	@echo "  make lint     ruff check"
	@echo "  make types    mypy"
	@echo "  make test     pytest"
	@echo "  make audit    pip-audit against the runtime lock file"

install:  ## Install pinned dev dependencies and the package
	$(PYTHON) -m pip install -r requirements-dev.lock
	$(PYTHON) -m pip install --no-deps -e .

check: lint format-check types test contracts roadmap audit  ## Run every pre-pull-request check
	@echo "All checks passed."

lint:
	$(PYTHON) -m ruff check src tests scripts

format-check:
	$(PYTHON) -m ruff format --check src tests scripts

types:
	$(PYTHON) -m mypy

test:
	$(PYTHON) -m pytest -q

contracts:
	$(PYTHON) scripts/export_contracts.py --check

roadmap:
	$(PYTHON) scripts/check_roadmap.py

audit:
	$(PYTHON) -m pip_audit -r requirements.lock
