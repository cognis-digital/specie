# Specie - developer convenience targets (macOS / Linux; Git Bash on Windows).
# For native Windows without make, use install.ps1 and the commands below.

VENV := .venv
PY   := $(VENV)/bin/python
PIP  := $(PY) -m pip
CLI  := $(VENV)/bin/specie

.PHONY: help install test demo lint clean

help:
	@echo "Targets:"
	@echo "  install  Create .venv and install specie (editable)"
	@echo "  test     Run the pytest suite"
	@echo "  demo     Run a representative CLI command + all example demos"
	@echo "  lint     ruff if available, else compileall"
	@echo "  clean    Remove venv, build artifacts, and caches"

install:
	python3 -m venv $(VENV) || python -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e .
	$(CLI) --help >/dev/null && echo "specie --help OK"

test: install
	$(PY) -m pytest -q

demo: install
	$(CLI) demo --stix bundle.stix.json --json product.json
	$(PY) examples/run_all_demos.py

lint: install
	@if $(PY) -m ruff --version >/dev/null 2>&1; then \
		$(PY) -m ruff check specie bench examples tests; \
	else \
		echo "ruff not installed; running compileall as a fallback"; \
		$(PY) -m compileall -q specie bench examples tests conftest.py; \
	fi

clean:
	rm -rf $(VENV) build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
