# Version stamped into the binary: the nearest git tag, or "dev" before the
# first commit.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.DEFAULT_GOAL := help

.PHONY: help build test vet up down reset clean

help: ## List the available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

build: ## Build bin/queryguard
	go build -ldflags "$(LDFLAGS)" -o bin/queryguard ./cmd/queryguard

test: ## Run the tests with the race detector
	go test -race ./...

vet: ## Run go vet
	go vet ./...

up: ## Start the Postgres containers and wait until they are healthy
	docker compose up -d --wait

down: ## Stop the Postgres containers, keeping their data
	docker compose down

reset: ## Stop the Postgres containers and delete their data
	docker compose down -v

clean: ## Delete build output
	rm -rf bin
