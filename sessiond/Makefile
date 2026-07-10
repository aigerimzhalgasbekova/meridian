GO ?= go

.PHONY: test test-int vet fmt check build run run-dev

fmt:
	gofmt -l .

check: vet test

run: run-dev

test:
	$(GO) test -race ./...

# REQUIRE_TEST_REDIS_URL turns an unset TEST_REDIS_URL into a failure instead
# of a suite that silently skips everything it exists to run.
test-int:
	REQUIRE_TEST_REDIS_URL=1 $(GO) test -race -tags integration ./...

vet:
	$(GO) vet ./...

build:
	$(GO) build -o bin/sessiond ./cmd/sessiond

run-dev:
	SESSIOND_DEV_MODE=1 SESSIOND_API_TOKENS=dev-service $(GO) run ./cmd/sessiond
