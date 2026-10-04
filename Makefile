# Version stamped into the binary: the nearest git tag, or "dev" before the
# first commit.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.DEFAULT_GOAL := help

.PHONY: help build test vet up down reset certs clean

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

certs: ## Make a self-signed TLS certificate for local testing in certs/
	mkdir -p certs
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
		-subj /CN=localhost -addext "subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1" \
		-keyout certs/server.key -out certs/server.crt
	chmod 600 certs/server.key

clean: ## Delete build output
	rm -rf bin
