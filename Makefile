.PHONY: help install dev demo test lint type scan-skills build serve clean

help:           ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n",$$1,$$2}'

install:        ## install the package + MCP server
	pip install '.[mcp]'

dev:            ## install with dev + mcp extras (for contributors)
	pip install -e '.[dev,mcp]'

demo:           ## run a threat model in TEST mode (templated fixtures, no key needed)
	@echo "a public REST API authenticates with JWT, calls an LLM agent, reads postgres; file upload supported" \
	  | synthesis analyze --doc - --mode fix --test

test:           ## run the offline test suite
	pytest -q

lint:           ## ruff lint
	ruff check synthesis_engine scripts tests

type:           ## mypy type-check
	mypy synthesis_engine

scan-skills:    ## run the skill injection-scan gate
	python scripts/scan_skills.py

build:          ## build sdist + wheel and confirm skills are packaged
	python -m build
	@echo "--- wheel contents (skills must appear) ---"
	@python -c "import glob,zipfile; w=sorted(glob.glob('dist/*.whl'))[-1]; \
print('\n'.join(n for n in zipfile.ZipFile(w).namelist() if 'skills/' in n))"

serve:          ## start the MCP server (stdio)
	synthesis serve

clean:          ## remove build/test artifacts
	rm -rf dist build *.egg-info .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
