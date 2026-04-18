SHELL := /bin/bash

CLI    := ./seagull
PYTHON ?= python3
PIP    ?= pip3

SYSTEMD_AGENT      ?= 0
DEV_REDIS_PERSIST  ?= 0

_SYSTEMD_AGENT_FLAG := $(if $(filter 1 true TRUE yes YES y Y,$(SYSTEMD_AGENT)),--systemd-agent,)
_PERSIST_FLAG       := $(if $(filter 1 true TRUE yes YES y Y,$(DEV_REDIS_PERSIST)),--persist,)

.PHONY: help \
  dev dev-persist dev-tls prod prod-fresh prod-setup prod-state-clear \
  agent-tokens-bootstrap prod-agent-tokens-bootstrap admin-reset \
  env-init prod-prepare \
  up up-extra up-observability prod-observability \
  down restart restart-persist restart-quick \
  systemd-agent-install systemd-agent-restart \
  ps logs build build-dev build-prod pull clean nuke psql \
  db-upgrade db-current \
  lint test test-detections deps-check redis-repair-aof ci

help:
	@$(CLI) --help

dev:
	@$(CLI) dev $(_SYSTEMD_AGENT_FLAG) $(_PERSIST_FLAG)

dev-persist:
	@$(CLI) dev --persist $(_SYSTEMD_AGENT_FLAG)

dev-tls:
	@$(CLI) dev --dev-reload $(_SYSTEMD_AGENT_FLAG)

prod:
	@$(CLI) prod

prod-fresh:
	@$(CLI) prod --fresh

prod-setup:
	@$(CLI) prod-setup

prod-state-clear:
	@$(CLI) state clear

agent-tokens-bootstrap:
	@$(CLI) agent tokens

prod-agent-tokens-bootstrap:
	@$(CLI) agent tokens --output-dir ./secrets/bootstrap

admin-reset:
	@$(CLI) admin reset

env-init:
	@$(CLI) env wizard

prod-prepare:
	@$(CLI) env prepare

up: dev

up-extra:
	@$(CLI) dev --extra $(_SYSTEMD_AGENT_FLAG)

up-observability:
	@$(CLI) observability

prod-observability:
	@$(CLI) observability --prod

down:
	@$(CLI) down

restart:
	@$(CLI) restart $(_SYSTEMD_AGENT_FLAG)

restart-persist:
	@$(CLI) restart --persist $(_SYSTEMD_AGENT_FLAG)

restart-quick:
	@$(CLI) restart --quick $(_SYSTEMD_AGENT_FLAG)

systemd-agent-install:
	@$(CLI) agent install

systemd-agent-restart:
	@$(CLI) agent restart

ps:
	@$(CLI) ps

logs:
	@$(CLI) logs $(SVC)

build: build-dev

build-dev:
	@$(CLI) build

build-prod:
	@$(CLI) build --prod

pull:
	@$(CLI) pull

clean:
	@$(CLI) clean

nuke:
	@$(CLI) nuke

psql:
	@$(CLI) psql

db-upgrade:
	@$(CLI) db upgrade

db-current:
	@$(CLI) db current

lint:
	@$(CLI) lint

test:
	@$(CLI) test

test-detections:
	@$(CLI) test --detections

deps-check:
	@$(CLI) deps-check

redis-repair-aof:
	@$(CLI) redis repair-aof

ci:
	@$(CLI) ci
