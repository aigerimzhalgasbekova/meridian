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
	$(GO) build -o bin/idpd ./cmd/idpd

run-dev:
	IDP_DEV_MODE=1 IDP_KEYSMITH_TOKEN=dev-signer IDP_REGISTRATION_TOKEN=dev-reg $(GO) run ./cmd/idpd
