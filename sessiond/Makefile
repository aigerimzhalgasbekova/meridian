GO ?= go

.PHONY: test vet build run-dev

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

build:
	$(GO) build -o bin/sessiond ./cmd/sessiond

run-dev:
	SESSIOND_DEV_MODE=1 SESSIOND_API_TOKENS=dev-service $(GO) run ./cmd/sessiond
