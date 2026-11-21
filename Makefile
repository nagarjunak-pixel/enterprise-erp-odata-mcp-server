.PHONY: sync lint typecheck test bench demo serve ui

sync:
	uv sync --python 3.13 --all-extras

lint:
	uv run ruff format --check src tests
	uv run ruff check src tests

typecheck:
	uv run mypy src tests

test:
	uv run pytest --cov=erp_odata_mcp --cov-report=term-missing --cov-fail-under=95

bench:
	uv run erp-odata-mcp bench

demo:
	uv run erp-odata-mcp demo

serve:
	uv run erp-odata-mcp serve --port 8270

ui:
	cd ui && npm ci && npm run build
