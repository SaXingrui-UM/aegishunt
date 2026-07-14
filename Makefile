.PHONY: install check lint typecheck test coverage doctor api frontend

install:
	python -m pip install -e ".[dev]"

lint:
	ruff check .

typecheck:
	mypy src

test:
	pytest

coverage:
	pytest --cov-report=term-missing --cov-report=html

check: lint typecheck test

doctor:
	aegishunt doctor

api:
	aegishunt api

frontend:
	aegishunt frontend
