GO ?= go
PY ?= python3

.PHONY: test test-py vet fmt check build run run-dev report

check: vet test test-py

run: run-dev

test:
	$(GO) test -race ./...

test-py:
	$(PY) -m unittest discover tools/compliance

vet:
	$(GO) vet ./...

fmt:
	gofmt -l .

build:
	$(GO) build -o bin/sentineld ./cmd/sentineld

run-dev:
	SENTINEL_TOKEN=dev-token SENTINEL_AUDIT_PATH=memory $(GO) run ./cmd/sentineld

report:
	$(PY) tools/compliance/report.py tools/compliance/testdata/sample_audit.jsonl
