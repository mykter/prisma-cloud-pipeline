.PHONY: build
build: version
	poetry build

# tried to use poetry-dynamic-versioning, but it messed up my python install in a big way.
.PHONY: version
version:
	poetry version $$(dunamai from any)

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

clean:
	rm -rf dist out/* prisma_cloud_pipeline/__pycache__