#
# Make 'make' more robust
#
SHELL := bash # Consistently use bash
.SHELLFLAGS  := -eu -o pipefail -c # Fail: if any command fails; if undefined variables are referenced; or if a command in a pipe fails
.DELETE_ON_ERROR: # Delete the rule target if the rule fails
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules # simplify make magic

.PHONY: build
build: version
	poetry build

# tried to use poetry-dynamic-versioning, but it messed up my python install in a big way.
.PHONY: version
version: # slightly convoluted approach to ensure that this fails if dunamai fails
	VERSION="$$(dunamai from any)" && [ -n "$$VERSION" ] && poetry version "$$VERSION"

.PHONY: lint
lint:
	python3 -m mypy --check-untyped-defs prisma_cloud_pipeline
	python3 -m pylint prisma_cloud_pipeline

.PHONY: test
test:
	[ -d out ] || mkdir out
	python3 -m prisma_cloud_pipeline --data=test/data.json --rules=example-rules.yaml --results=out/test-results.json --triaged-findings=out/test-triaged.json --finding-stats > out/test-stdout
	diff --brief out/test-stdout test/spec-stdout
	diff --brief out/test-results.json test/spec-results.json
	diff --brief out/test-triaged.json test/spec-triaged.json

.PHONY: clean
clean:
	rm -rf dist out/* prisma_cloud_pipeline/__pycache__