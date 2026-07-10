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

# :8083 matches scripts/dev-all.sh and every doc. The code default is :8080,
# the in-container port compose and ECS publish behind :8083; standalone it
# would collide with idp.
run-dev:
	BRIDGE_DEV_MODE=1 BRIDGE_ADDR=:8083 $(GO) run ./cmd/bridged
