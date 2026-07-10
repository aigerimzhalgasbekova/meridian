GO ?= go

.PHONY: test vet fmt check build run run-dev

fmt:
	gofmt -l .

check: vet test

run: run-dev

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

build:
	$(GO) build -o bin/bridged ./cmd/bridged

run-dev:
	BRIDGE_DEV_MODE=1 $(GO) run ./cmd/bridged
