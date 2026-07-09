GO ?= go

.PHONY: test bench vet build run-dev

test:
	$(GO) test -race ./...

bench:
	$(GO) test -bench=. -benchmem -run=^$$ ./jose/

vet:
	$(GO) vet ./...

build:
	$(GO) build -o bin/keysmithd ./cmd/keysmithd

run-dev:
	KEYSMITH_DEV_MODE=1 KEYSMITH_SIGNER_TOKENS=dev-signer KEYSMITH_ADMIN_TOKENS=dev-admin $(GO) run ./cmd/keysmithd
