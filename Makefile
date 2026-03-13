SHELL := /bin/bash

DC := docker compose
COMPOSE_BASE := -f docker-compose.yml
COMPOSE_DEV := $(COMPOSE_BASE) -f compose.dev.yml
COMPOSE_DEV_TLS := $(COMPOSE_DEV) -f compose.dev.tls.yml
COMPOSE_PROD := $(COMPOSE_BASE) -f compose.prod.yml

ENV_FILE := .env
ENV_EXAMPLE := .env.example

PYTHON ?= python3
PIP ?= pip3

.PHONY: help bootstrap bootstrap-tools certs-bootstrap dev dev-tls prod up up-extra down restart ps logs build build-dev build-prod pull clean nuke psql db-upgrade db-current lint test test-detections deps-check ci

help:
	@echo "Targets:"
	@echo "  make dev         - bootstrap and start development stack"
	@echo "  make dev-tls     - start development stack with stricter HTTPS cookie/proxy settings"
	@echo "  make prod        - bootstrap and start production-style stack"
	@echo "  make up          - alias for make dev"
	@echo "  make up-extra    - start development stack with profile 'extra'"
	@echo "  make down        - stop stack (dev profile by default)"
	@echo "  make restart     - restart development stack"
	@echo "  make ps          - list services (dev profile by default)"
	@echo "  make logs        - follow logs (set SVC=service)"
	@echo "  make build-dev   - build dev images"
	@echo "  make build-prod  - build prod images"
	@echo "  make db-upgrade  - run alembic upgrade head in backend container"
	@echo "  make db-current  - show current alembic revision in backend container"
	@echo "  make lint        - lint backend, frontend and agent"
	@echo "  make test        - run minimal automated tests"
	@echo "  make test-detections - run detection content validation suite"
	@echo "  make deps-check  - dependency vulnerability checks"
	@echo "  make ci          - run local CI sequence (lint, test, build-prod)"
	@echo "  make clean       - down + remove-orphans (keeps volumes)"
	@echo "  make nuke        - down + remove volumes (DANGEROUS)"
	@echo "  make psql        - open psql inside postgres"

bootstrap:
	@./scripts/bootstrap_env.sh $(ENV_FILE) $(ENV_EXAMPLE)

bootstrap-tools:
	@command -v docker >/dev/null 2>&1 || (echo "docker not found" && exit 1)
	@docker compose version >/dev/null 2>&1 || (echo "docker compose not available" && exit 1)

certs-bootstrap: bootstrap
	@AUTO_GENERATE_CERTS="$${NETWATCH_AUTO_GENERATE_CERTS:-true}"; \
	if [ "$$AUTO_GENERATE_CERTS" = "true" ]; then \
		echo "[bootstrap] regenerating edge+agent certificates"; \
		./scripts/pki/bootstrap_runtime_certs.sh; \
	else \
		echo "[bootstrap] NETWATCH_AUTO_GENERATE_CERTS=false (skipping cert regeneration)"; \
	fi

# Single-command bootstrap for development.
dev: bootstrap bootstrap-tools certs-bootstrap
	$(DC) $(COMPOSE_DEV) up -d --build

dev-tls: bootstrap bootstrap-tools certs-bootstrap
	$(DC) $(COMPOSE_DEV_TLS) up -d --build

# Single-command bootstrap for production-like runs.
prod: bootstrap bootstrap-tools certs-bootstrap
	$(DC) $(COMPOSE_PROD) up -d --build

up: dev

up-extra: bootstrap bootstrap-tools certs-bootstrap
	$(DC) $(COMPOSE_DEV) --profile extra up -d --build

down:
	$(DC) $(COMPOSE_DEV) down

restart:
	$(DC) $(COMPOSE_DEV) down
	$(DC) $(COMPOSE_DEV) up -d --build

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
