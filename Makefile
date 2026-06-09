.PHONY: sync fmt lint type test check cov clean

sync:
	uv sync --dev --all-extras

fmt:
	uv run ruff format .

lint:
	uv run ruff check .

type:
	uv run mypy

test:
	uv run pytest -q

check: fmt lint type test

cov:
	uv run pytest --cov --cov-report=term-missing -q

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .mypy_cache .ruff_cache .pytest_cache htmlcov .coverage
