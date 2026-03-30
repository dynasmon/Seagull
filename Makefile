SHELL := /bin/bash

DC := docker compose
COMPOSE_BASE := -f docker-compose.yml
COMPOSE_DEV := $(COMPOSE_BASE) -f compose.dev.yml
COMPOSE_DEV_TLS := $(COMPOSE_DEV) -f compose.dev.tls.yml
COMPOSE_PROD := $(COMPOSE_BASE) -f compose.prod.yml

ENV_FILE := .env
ENV_EXAMPLE := .env.example
PROD_CORE_SERVICES := postgres redis elasticsearch clickhouse netwatch-backend netwatch-ingest-worker netwatch-rules-worker netwatch-audit-retention netwatch-es-indexer netwatch-rollup-worker netwatch-ip-intel netwatch-proto-intel netwatch-attack-chain netwatch-portal caddy grafana
PROD_AGENT_SERVICES := netwatch-agent-core netwatch-agent-sensor

PYTHON ?= python3
PIP ?= pip3

.PHONY: help bootstrap bootstrap-tools agent-tokens-bootstrap prod-agent-tokens-bootstrap admin-reset dev-preflight env-init prod-setup prod-prepare prod-fresh prod-state-clear dev dev-tls prod up up-extra down restart restart-quick ps logs build build-dev build-prod pull clean nuke psql db-upgrade db-current lint test test-detections deps-check ci

help:
	@echo "Targets:"
	@echo "  make dev           - bootstrap and start development stack"
	@echo "  make dev-preflight - validate local prerequisites for make dev"
	@echo "  make dev-tls       - start development stack with stricter HTTPS cookie/proxy settings"
	@echo "  make env-init      - interactive wizard for critical production .env values"
	@echo "  make prod-setup    - run env wizard, validate prod config, then stop"
	@echo "  make prod          - bootstrap and start production-style stack (auto-heals first-run drift)"
	@echo "  make prod-fresh    - full fresh production-style boot (drops runtime volumes)"
	@echo "  make admin-reset   - reset/sync bootstrap admin password"
	@echo "  make up            - alias for make dev"
	@echo "  make up-extra      - start development stack with profile 'extra'"
	@echo "  make down          - stop stack (dev profile by default)"
	@echo "  make restart       - restart development stack"
	@echo "  make restart-quick - restart development containers without rebuild"
	@echo "  make ps            - list services (dev profile by default)"
	@echo "  make logs          - follow logs (set SVC=service)"
	@echo "  make build-dev     - build dev images"
	@echo "  make build-prod    - build prod images"
	@echo "  make db-upgrade    - run alembic upgrade head in backend container"
	@echo "  make db-current    - show current alembic revision in backend container"
	@echo "  make lint          - lint backend, frontend and agent"
	@echo "  make test          - run minimal automated tests"
	@echo "  make test-detections - run detection content validation suite"
	@echo "  make deps-check    - dependency vulnerability checks"
	@echo "  make ci            - run local CI sequence (lint, test, build-prod)"
	@echo "  make clean         - down + remove-orphans (keeps volumes)"
	@echo "  make nuke          - down + remove volumes (DANGEROUS)"
	@echo "  make psql          - open psql inside postgres"

bootstrap:
	@./scripts/bootstrap_env.sh $(ENV_FILE) $(ENV_EXAMPLE)

bootstrap-tools:
	@command -v docker >/dev/null 2>&1 || (echo "docker not found" && exit 1)
	@docker compose version >/dev/null 2>&1 || (echo "docker compose not available" && exit 1)

dev-preflight: bootstrap bootstrap-tools
	@./scripts/dev_preflight.sh

agent-tokens-bootstrap:
	@./scripts/mint_agent_bootstrap_tokens.sh

prod-agent-tokens-bootstrap:
	@NETWATCH_MINT_TOKENS_OUTPUT_DIR=./secrets/bootstrap ./scripts/mint_agent_bootstrap_tokens.sh

admin-reset: bootstrap bootstrap-tools
	$(DC) $(COMPOSE_PROD) run --rm --build -T netwatch-backend python -m app.cli admin-reset

env-init: bootstrap
	@./scripts/env_wizard.sh

prod-setup: bootstrap bootstrap-tools env-init prod-prepare
	@echo "[prod-setup] environment wizard completed and production config validated"

prod-prepare: bootstrap
	@./scripts/prod_prepare.sh

# Single-command bootstrap for development.
dev: dev-preflight
	$(DC) $(COMPOSE_DEV) up -d --build --force-recreate
	@$(MAKE) agent-tokens-bootstrap
	$(DC) $(COMPOSE_DEV) up -d --force-recreate netwatch-agent-core netwatch-agent-sensor

dev-tls: dev-preflight
	$(DC) $(COMPOSE_DEV_TLS) up -d --build --force-recreate
	@$(MAKE) agent-tokens-bootstrap
	$(DC) $(COMPOSE_DEV_TLS) up -d --force-recreate netwatch-agent-core netwatch-agent-sensor

# Single-command bootstrap for production-like runs.
prod: bootstrap bootstrap-tools prod-prepare
	@reset_required=false; \
	if ! ./scripts/prod_state_guard.sh check; then \
		status=$$?; \
		if [ $$status -eq 10 ]; then \
			reset_required=true; \
		else \
			exit $$status; \
		fi; \
	fi; \
	if [ "$$reset_required" = "true" ]; then \
		echo "[prod] resetting named runtime volumes due to configuration drift"; \
		$(DC) $(COMPOSE_PROD) down -v --remove-orphans; \
		rm -f ./secrets/bootstrap/*.token; \
		./scripts/prod_state_guard.sh clear; \
	fi
	$(DC) $(COMPOSE_PROD) down --remove-orphans
	$(DC) $(COMPOSE_PROD) up -d --build --remove-orphans $(PROD_CORE_SERVICES)
	@$(MAKE) prod-agent-tokens-bootstrap
	$(DC) $(COMPOSE_PROD) up -d --force-recreate $(PROD_AGENT_SERVICES)
	@./scripts/prod_state_guard.sh commit

prod-fresh: bootstrap bootstrap-tools prod-prepare
	$(DC) $(COMPOSE_PROD) down -v --remove-orphans
	@rm -f ./secrets/bootstrap/*.token
	@./scripts/prod_state_guard.sh clear
	$(DC) $(COMPOSE_PROD) up -d --build --remove-orphans $(PROD_CORE_SERVICES)
	@$(MAKE) prod-agent-tokens-bootstrap
	$(DC) $(COMPOSE_PROD) up -d --force-recreate $(PROD_AGENT_SERVICES)
	@./scripts/prod_state_guard.sh commit

prod-state-clear:
	@./scripts/prod_state_guard.sh clear

up: dev

up-extra: dev-preflight
	$(DC) $(COMPOSE_DEV) --profile extra up -d --build --force-recreate
	@$(MAKE) agent-tokens-bootstrap
	$(DC) $(COMPOSE_DEV) --profile extra up -d --force-recreate netwatch-agent-core netwatch-agent-sensor netwatch-agent-lateral

down:
	$(DC) $(COMPOSE_DEV) down

restart: dev-preflight
	$(DC) $(COMPOSE_DEV) down
	$(DC) $(COMPOSE_DEV) up -d --build

restart-quick:
	$(DC) $(COMPOSE_DEV) restart

ps:
	$(DC) $(COMPOSE_DEV) ps

logs:
	@if [ -z "$(SVC)" ]; then \
		$(DC) $(COMPOSE_DEV) logs -f; \
	else \
		$(DC) $(COMPOSE_DEV) logs -f $(SVC); \
	fi

build: build-dev

build-dev:
	$(DC) $(COMPOSE_DEV) build

build-prod:
	$(DC) $(COMPOSE_PROD) build

pull:
	$(DC) $(COMPOSE_BASE) pull

clean:
	$(DC) $(COMPOSE_DEV) down --remove-orphans

nuke:
	$(DC) $(COMPOSE_DEV) down -v --remove-orphans

psql:
	$(DC) $(COMPOSE_DEV) exec postgres psql -U $$POSTGRES_USER -d $$POSTGRES_DB

db-upgrade:
	$(DC) $(COMPOSE_DEV) run --rm --build netwatch-backend python -m alembic upgrade head

db-current:
	$(DC) $(COMPOSE_DEV) run --rm --build netwatch-backend python -m alembic current

lint:
	cd backend && $(PYTHON) -m ruff check app tests
	cd frontend && npm run lint
	cd agent && test -z "$$(gofmt -l $$(find . -name '*.go' -type f))" || (echo "gofmt required on agent sources" && exit 1)
	cd agent && go vet ./...

test:
	cd backend && $(PYTHON) -m pytest -q
	cd agent && go test ./...
	cd frontend && npm run smoke

test-detections:
	cd backend && $(PYTHON) -m pytest -q tests/test_rules_and_correlations.py tests/test_detection_catalog.py

deps-check:
	cd backend && $(PYTHON) -m pip_audit -r requirements.lock
	cd frontend && npm audit --audit-level=high
	cd agent && go install golang.org/x/vuln/cmd/govulncheck@latest
	cd agent && govulncheck ./...

ci: lint test build-prod
