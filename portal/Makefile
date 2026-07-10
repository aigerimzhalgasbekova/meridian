NPM ?= npm

.PHONY: install test test-int typecheck build dev docker

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
