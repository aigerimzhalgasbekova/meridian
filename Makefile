# Root fan-out. Each project also has its own Makefile with the same verbs.
GO_MODULES := keysmith idp sessiond sentinel bridge console

.PHONY: test fmt vet check compose-up compose-down smoke site dev

# Everything that runs with no external services: all Go modules (-race),
# portal (vitest), sentinel's Python compliance suite.
test:
	@for m in $(GO_MODULES); do echo "== $$m"; $(MAKE) -C $$m test || exit 1; done
	@echo "== portal"; $(MAKE) -C portal test
	@echo "== sentinel (python)"; $(MAKE) -C sentinel test-py

# Lists files gofmt would change (empty output = clean).
fmt:
	@for m in $(GO_MODULES); do $(MAKE) -s -C $$m fmt; done

vet:
	@for m in $(GO_MODULES); do echo "== $$m"; $(MAKE) -C $$m vet || exit 1; done

check: vet test
	$(MAKE) -C portal typecheck

# Full local stack (Docker): all 7 services + Postgres + Redis.
compose-up:
	cd platform/compose && docker compose up -d --build

compose-down:
	cd platform/compose && docker compose down

smoke:
	cd platform/compose && ./smoke.sh

site:
	cd site && npm run build

# All services in zero-dependency dev mode, no Docker.
dev:
	./scripts/dev-all.sh
