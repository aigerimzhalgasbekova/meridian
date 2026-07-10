GO ?= go
NPM ?= npm

.PHONY: test vet fmt check build web run run-dev

fmt:
	gofmt -l .

check: vet test

run: run-dev

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

build:
	$(GO) build -o bin/consoled ./cmd/consoled

web:
	cd web && $(NPM) install && $(NPM) run build

run-dev:
	CONSOLE_DEV_MODE=1 CONSOLE_WEB_DIR=web/dist $(GO) run ./cmd/consoled
