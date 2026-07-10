GO ?= go

.PHONY: test test-int vet fmt check build run run-dev

fmt:
	gofmt -l .

check: vet test

run: run-dev

test:
	$(GO) test -race ./...

test-int:
	$(GO) test -race -tags integration ./...

vet:
	$(GO) vet ./...

build:
	$(GO) build -o bin/sessiond ./cmd/sessiond

run-dev:
	SESSIOND_DEV_MODE=1 SESSIOND_API_TOKENS=dev-service $(GO) run ./cmd/sessiond
