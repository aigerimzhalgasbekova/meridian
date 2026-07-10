NPM ?= npm

.PHONY: install test test-int typecheck check build dev run docker

check: typecheck test

run: dev

install:
	$(NPM) install

test:
	$(NPM) test

# Requires TEST_DATABASE_URL pointing at a scratch Postgres database.
test-int:
	$(NPM) test

typecheck:
	$(NPM) run typecheck

build:
	$(NPM) run build

dev:
	$(NPM) run dev

docker:
	docker build -t meridian/portal .
