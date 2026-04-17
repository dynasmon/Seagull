SHELL := /bin/bash

DC := docker compose
COMPOSE_BASE := \
  -f compose.base.yml \
  -f compose.data.yml \
  -f compose.backend.yml \
  -f compose.portal.yml \
  -f compose.observability.yml \
  -f compose.agents.yml
COMPOSE_DEV := $(COMPOSE_BASE) -f compose.dev.yml
COMPOSE_DEV_TLS := $(COMPOSE_DEV) -f compose.dev.tls.yml
COMPOSE_PROD := $(COMPOSE_BASE) -f compose.prod.yml

ENV_FILE := .env
ENV_EXAMPLE := .env.example
PROD_CORE_SERVICES := postgres redis elasticsearch clickhouse seagull-backend seagull-ingest-pipeline seagull-intelligence-worker seagull-maintenance-worker seagull-portal caddy
PROD_AGENT_SERVICES := seagull-agent-core seagull-agent-sensor
SYSTEMD_AGENT ?= 0
DEV_REDIS_PERSIST ?= 0
SYSTEMD_AGENT_ENABLED := $(filter 1 true TRUE yes YES y Y,$(SYSTEMD_AGENT))
DEV_REDIS_PERSIST_ENABLED := $(filter 1 true TRUE yes YES y Y,$(DEV_REDIS_PERSIST))
DEV_DOCKER_AGENT_SCALE_ARGS :=
DEV_DOCKER_AGENT_SERVICES := seagull-agent-core seagull-agent-sensor
DEV_COMPOSE_FILES := $(COMPOSE_DEV)
DEV_TLS_COMPOSE_FILES := $(COMPOSE_DEV_TLS)
DEV_REDIS_ENV :=

ifneq ($(SYSTEMD_AGENT_ENABLED),)
DEV_DOCKER_AGENT_SCALE_ARGS := --scale seagull-agent-core=0 --scale seagull-agent-sensor=0
DEV_DOCKER_AGENT_SERVICES :=
endif

ifneq ($(DEV_REDIS_PERSIST_ENABLED),)
DEV_REDIS_ENV := SEAGULL_REDIS_DEV_CONFIG=redis.dev.persist.conf SEAGULL_REDIS_STOP_GRACE_PERIOD=30s
endif

PYTHON ?= python3
PIP ?= pip3

.PHONY: help bootstrap bootstrap-tools agent-tokens-bootstrap prod-agent-tokens-bootstrap admin-reset dev-preflight env-init prod-setup prod-prepare prod-fresh prod-state-clear dev dev-persist dev-tls prod up up-extra up-observability prod-observability down restart restart-persist restart-quick systemd-agent-install systemd-agent-restart ps logs build build-dev build-prod pull clean nuke psql db-upgrade db-current lint test test-detections deps-check redis-repair-aof ci

help:
	@echo "Targets:"
	@echo "  make dev           - bootstrap and start development stack"
	@echo "  make dev-persist   - start development stack with persistent Redis"
	@echo "  make dev-tls       - start development stack with stricter HTTPS cookie/proxy settings"
	@echo "  make restart       - restart development stack"
	@echo "  make restart-persist - restart development stack with persistent Redis"
	@echo "  * use SYSTEMD_AGENT=1 for host-managed agents"
	@echo "  * use DEV_REDIS_PERSIST=1 to keep Redis state in dev"
	@echo "  make env-init      - interactive wizard for critical production .env values"
	@echo "  make prod-setup    - run env wizard, validate prod config, then stop"
	@echo "  make prod          - bootstrap and start production-style stack (auto-heals first-run drift)"
	@echo "  make prod-fresh    - full fresh production-style boot (drops runtime volumes)"
	@echo "  make admin-reset   - reset/sync bootstrap admin password"
	@echo "  make up            - alias for make dev"
	@echo "  make up-extra      - start development stack with profile 'extra'"
	@echo "  make up-observability - start optional Grafana/Kibana profile in development"
	@echo "  make prod-observability - start optional Grafana/Kibana profile in production"
	@echo "  make redis-repair-aof - back up and repair persistent Redis AOF state"
	@echo "  make down          - stop stack (dev profile by default)"
	@echo "  make restart-quick - recreate development containers without rebuild"
	@echo "  make systemd-agent-install - install/update the host systemd seagull-agent deployment"
	@echo "  make systemd-agent-restart - restart only host systemd seagull-agent service"
	@echo "  make ps            - list services (dev profile by default)"
	@echo "  make logs          - follow logs (set SVC=service)"
	@echo "  make build-dev     - build dev images"
	@echo "  make build-prod    - build prod images"
	@echo "  make db-upgrade    - run alembic upgrade head in backend container"
	@echo "  make db-current    - show current alembic revision in backend container"
	@echo "  make dev-preflight - validate local prerequisites for make dev"
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
	@SEAGULL_MINT_TOKENS_OUTPUT_DIR=./secrets/bootstrap ./scripts/mint_agent_bootstrap_tokens.sh

admin-reset: bootstrap bootstrap-tools
	$(DC) $(COMPOSE_PROD) run --rm --build -T seagull-backend python -m app.cli admin-reset

env-init: bootstrap
	@./scripts/env_wizard.sh

prod-setup: bootstrap bootstrap-tools env-init prod-prepare
	@echo "[prod-setup] environment wizard completed and production config validated"

prod-prepare: bootstrap
	@./scripts/prod_prepare.sh

# Single-command bootstrap for development.
dev: dev-preflight
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) up -d --build --force-recreate --remove-orphans $(DEV_DOCKER_AGENT_SCALE_ARGS)
ifneq ($(SYSTEMD_AGENT_ENABLED),)
	@echo "[dev] SYSTEMD_AGENT=$(SYSTEMD_AGENT) -> skipping docker agent bootstrap/recreate"
else
	@$(MAKE) agent-tokens-bootstrap
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) up -d --force-recreate --remove-orphans $(DEV_DOCKER_AGENT_SERVICES)
endif

dev-persist: DEV_REDIS_PERSIST=1
dev-persist: dev

dev-tls: dev-preflight
	$(DEV_REDIS_ENV) $(DC) $(DEV_TLS_COMPOSE_FILES) up -d --build --force-recreate --remove-orphans $(DEV_DOCKER_AGENT_SCALE_ARGS)
ifneq ($(SYSTEMD_AGENT_ENABLED),)
	@echo "[dev-tls] SYSTEMD_AGENT=$(SYSTEMD_AGENT) -> skipping docker agent bootstrap/recreate"
else
	@$(MAKE) agent-tokens-bootstrap
	$(DEV_REDIS_ENV) $(DC) $(DEV_TLS_COMPOSE_FILES) up -d --force-recreate --remove-orphans $(DEV_DOCKER_AGENT_SERVICES)
endif

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
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) --profile extra up -d --build --force-recreate --remove-orphans $(DEV_DOCKER_AGENT_SCALE_ARGS)
ifneq ($(SYSTEMD_AGENT_ENABLED),)
	@echo "[up-extra] SYSTEMD_AGENT=$(SYSTEMD_AGENT) -> skipping docker agent bootstrap/recreate for core/sensor"
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) --profile extra up -d --force-recreate --remove-orphans seagull-agent-lateral
else
	@$(MAKE) agent-tokens-bootstrap
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) --profile extra up -d --force-recreate --remove-orphans seagull-agent-core seagull-agent-sensor seagull-agent-lateral
endif

up-observability: dev-preflight
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) --profile observability up -d --build grafana kibana

prod-observability: bootstrap bootstrap-tools prod-prepare
	$(DC) $(COMPOSE_PROD) --profile observability up -d --build grafana kibana

down:
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) down --remove-orphans

restart: dev-preflight
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) down --remove-orphans
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) up -d --build --remove-orphans $(DEV_DOCKER_AGENT_SCALE_ARGS)

restart-persist: DEV_REDIS_PERSIST=1
restart-persist: restart

restart-quick: dev-preflight
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) up -d --force-recreate --remove-orphans $(DEV_DOCKER_AGENT_SCALE_ARGS)

systemd-agent-install:
	sudo env AUTO_START_IF_READY=1 bash deploy/systemd/install-agent.sh

systemd-agent-restart:
	sudo systemctl restart seagull-agent
	sudo systemctl status seagull-agent --no-pager

ps:
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) ps

logs:
	@if [ -z "$(SVC)" ]; then \
		$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) logs -f; \
	else \
		$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) logs -f $(SVC); \
	fi

build: build-dev

build-dev:
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) build

build-prod:
	$(DC) $(COMPOSE_PROD) build

pull:
	$(DC) $(COMPOSE_BASE) pull

clean:
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) down --remove-orphans

nuke:
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) down -v --remove-orphans

psql:
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) exec postgres psql -U $$POSTGRES_USER -d $$POSTGRES_DB

db-upgrade:
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) run --rm --build seagull-backend python -m alembic upgrade head

db-current:
	$(DEV_REDIS_ENV) $(DC) $(DEV_COMPOSE_FILES) run --rm --build seagull-backend python -m alembic current

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

redis-repair-aof:
	@sh ./scripts/redis/repair-aof.sh

ci: lint test build-prod
