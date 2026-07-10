NPM ?= npm

.PHONY: install test test-int typecheck check build dev run docker

check: typecheck test

run: dev

install:
	$(NPM) install

test:
	$(NPM) test

# Same suite as `test`, but REQUIRE_TEST_DATABASE_URL turns an unset
# TEST_DATABASE_URL into a failure instead of 23 silently skipped tests.
test-int:
	REQUIRE_TEST_DATABASE_URL=1 $(NPM) test

typecheck:
	$(NPM) run typecheck

build:
	$(NPM) run build

dev:
	$(NPM) run dev

docker:
	docker build -t meridian/portal .
