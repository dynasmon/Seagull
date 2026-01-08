SHELL := /bin/bash
DC := docker compose

ENV_FILE := .env
ENV_EXAMPLE := .env.example

.PHONY: help bootstrap up up-extra down restart ps logs build pull clean nuke psql

help:
	@echo "Targets:"
	@echo "  make up         - create .env if missing and start the stack"
	@echo "  make up-extra   - same as up, but enables profile 'extra' (lateral agent)"
	@echo "  make down       - stop the stack"
	@echo "  make restart    - restart the stack"
	@echo "  make ps         - list services"
	@echo "  make logs       - follow logs (set SVC=service)"
	@echo "  make build      - build images"
	@echo "  make pull       - pull images"
	@echo "  make clean      - down + remove-orphans (keeps volumes)"
	@echo "  make nuke       - down + remove volumes (DANGEROUS)"
	@echo "  make psql       - open psql inside postgres"

bootstrap:
	@test -f $(ENV_FILE) || (cp $(ENV_EXAMPLE) $(ENV_FILE) && echo "[bootstrap] created .env from .env.example")

up: bootstrap
	$(DC) up -d --build

up-extra: bootstrap
	$(DC) --profile extra up -d --build

down:
	$(DC) down

restart:
	$(DC) down
	$(DC) up -d --build

ps:
	$(DC) ps

logs:
	@if [ -z "$(SVC)" ]; then \
		$(DC) logs -f; \
	else \
		$(DC) logs -f $(SVC); \
	fi

build:
	$(DC) build

pull:
	$(DC) pull

clean:
	$(DC) down --remove-orphans

nuke:
	$(DC) down -v --remove-orphans

psql:
	$(DC) exec postgres psql -U $$POSTGRES_USER -d $$POSTGRES_DB
