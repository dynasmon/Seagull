SHELL := /bin/bash
CLI   := ./seagull

.PHONY: help \
  up down restart status logs doctor reset \
  dev prod dev-persist dev-reload prod-fresh prod-setup prod-state-clear \
  admin-reset agent-tokens \
  systemd-install systemd-restart systemd-status systemd-validate \
  up-extra observability \
  build build-prod pull clean nuke psql \
  db-upgrade db-current \
  lint test test-detections deps-check ci redis-repair-aof geoip

# Primary interface

help:
	@$(CLI) --help

up:
	@$(CLI) up $(ARGS)

down:
	@$(CLI) down

restart:
	@$(CLI) restart $(ARGS)

status:
	@$(CLI) status

logs:
	@$(CLI) logs $(SVC)

doctor:
	@$(CLI) doctor

reset:
	@$(CLI) reset $(ARGS)

# Stack variants

dev-persist:
	@$(CLI) up --mode dev --persist

dev-reload:
	@$(CLI) up --mode dev --dev-reload

prod-fresh:
	@$(CLI) up --mode prod --fresh

# Environment / setup

env-init:
	@$(CLI) env wizard

prod-setup:
	@$(CLI) prod-setup

prod-state-clear:
	@$(CLI) state clear

# Agent operations

admin-reset:
	@$(CLI) admin reset

agent-tokens:
	@$(CLI) agent tokens

systemd-install:
	@$(CLI) agent install-systemd

systemd-restart:
	@$(CLI) agent restart-systemd

systemd-status:
	@$(CLI) agent status-systemd

systemd-validate:
	@$(CLI) agent validate-systemd

# Optional profiles

up-extra:
	@$(CLI) dev --extra

observability:
	@$(CLI) observability

# Image management

build build-prod:
	@$(CLI) build

pull:
	@$(CLI) pull

# DB / utilities

db-upgrade:
	@$(CLI) db upgrade

db-current:
	@$(CLI) db current

psql:
	@$(CLI) psql

clean:
	@$(CLI) clean

nuke:
	@$(CLI) nuke

redis-repair-aof:
	@$(CLI) redis repair-aof

# GeoIP databases

geoip:
	@$(CLI) geoip install

# CI / quality

lint:
	@$(CLI) lint

test:
	@$(CLI) test

test-detections:
	@$(CLI) test --detections

deps-check:
	@$(CLI) deps-check

ci:
	@$(CLI) ci

# Compatibility wrappers (deprecated)

dev:
	@echo "[seagull] 'make dev' is deprecated — use: ./seagull up --mode dev" >&2
	@$(CLI) up --mode dev $(ARGS)

prod:
	@echo "[seagull] 'make prod' is deprecated — use: ./seagull up --mode prod" >&2
	@$(CLI) up --mode prod $(ARGS)
