.PHONY: install check lint typecheck test coverage doctor init-db api frontend \
	package package-check docs-delivery release-bundle docker-config docker-build

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

init-db:
	aegishunt init-db

api:
	aegishunt api

frontend:
	aegishunt frontend

package:
	python -m build

package-check:
	python -m twine check dist/*
	PYTHONPATH=src python -m scripts.verify_phase14_distribution \
		--wheel "$$(find dist -maxdepth 1 -name '*.whl' -print -quit)" \
		--sdist "$$(find dist -maxdepth 1 -name '*.tar.gz' -print -quit)"

docs-delivery:
	PYTHONPATH=src python -m scripts.validate_phase14_delivery

release-bundle: package package-check docs-delivery
	PYTHONPATH=src python -m scripts.build_release_bundle build

docker-config:
	docker compose config --quiet

docker-build:
	docker compose build --no-cache
