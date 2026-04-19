SHELL := /bin/bash

CLI    := ./seagull
PYTHON ?= python3

SYSTEMD_AGENT     ?= 0
DEV_REDIS_PERSIST ?= 0

_AGENT_MODE   := $(if $(filter 1 true TRUE yes YES y Y,$(SYSTEMD_AGENT)),--agent-mode systemd,)
_PERSIST      := $(if $(filter 1 true TRUE yes YES y Y,$(DEV_REDIS_PERSIST)),--persist,)
_LEGACY_AGENT := $(if $(filter 1 true TRUE yes YES y Y,$(SYSTEMD_AGENT)),--systemd-agent,)

.PHONY: help \
  up dev prod \
  down restart status logs doctor reset \
  dev-persist dev-tls \
  prod-fresh prod-setup prod-state-clear \
  agent-tokens-bootstrap prod-agent-tokens-bootstrap \
  admin-reset env-init prod-prepare \
  up-extra up-observability prod-observability \
  restart-persist restart-quick \
  systemd-agent-install systemd-agent-restart \
  ps build pull clean nuke psql \
  db-upgrade db-current \
  lint test test-detections deps-check redis-repair-aof ci

help:
	@$(CLI) --help

up:
	@$(CLI) up $(_AGENT_MODE) $(_PERSIST)

dev:
	@$(CLI) up --mode dev $(_AGENT_MODE) $(_PERSIST)

prod:
	@$(CLI) up --mode prod $(_AGENT_MODE)

down:
	@$(CLI) down

restart:
	@$(CLI) restart $(_LEGACY_AGENT) $(_PERSIST)

status:
	@$(CLI) status

logs:
	@$(CLI) logs $(SVC)

doctor:
	@$(CLI) doctor

reset:
	@$(CLI) reset

dev-persist:
	@$(CLI) up --mode dev --persist $(_AGENT_MODE)

dev-tls:
	@$(CLI) up --mode dev --dev-reload $(_AGENT_MODE)

prod-fresh:
	@$(CLI) up --mode prod --fresh

prod-setup:
	@$(CLI) prod-setup

prod-state-clear:
	@$(CLI) state clear

agent-tokens-bootstrap:
	@$(CLI) agent tokens

prod-agent-tokens-bootstrap:
	@$(CLI) agent tokens --output-dir ./secrets/bootstrap

systemd-agent-install:
	@$(CLI) agent install

systemd-agent-restart:
	@$(CLI) agent restart

admin-reset:
	@$(CLI) admin reset

env-init:
	@$(CLI) env wizard

prod-prepare:
	@$(CLI) env prepare

up-extra:
	@$(CLI) dev --extra $(_LEGACY_AGENT)

up-observability:
	@$(CLI) observability

prod-observability:
	@$(CLI) observability

restart-persist:
	@$(CLI) restart --persist $(_LEGACY_AGENT)

restart-quick:
	@$(CLI) restart --quick $(_LEGACY_AGENT)

ps:
	@$(CLI) ps

build:
	@$(CLI) build

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
