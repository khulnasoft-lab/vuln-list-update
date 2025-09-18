export SHELL := /bin/bash
export SHELLOPTS := errexit

GOPATH ?= $(shell go env GOPATH)
BIN_DIR := $(GOPATH)/bin
GOLANGCI_LINT := $(BIN_DIR)/golangci-lint
GOLANGCI_LINT_VERSION := v2.0.0

.PHONY: lint lintfix test build ensure-golangci

ensure-golangci:
	@set -e; \
	CUR_VER=""; \
	if [ -x "$(GOLANGCI_LINT)" ]; then \
	  CUR_VER="$$($(GOLANGCI_LINT) version 2>/dev/null | head -n1 | sed -E 's/.*version ([^ ]+).*/\1/')"; \
	fi; \
	if [ -z "$$CUR_VER" ] || ! echo "$$CUR_VER" | grep -q '^v2\.'; then \
	  echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION) via go install (was: $${CUR_VER:-none})"; \
	  GOBIN=$(BIN_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
	else \
	  echo "golangci-lint $$CUR_VER is already v2.x"; \
	fi

lint: ensure-golangci
	@$(GOLANGCI_LINT) run

lintfix: ensure-golangci
	@$(GOLANGCI_LINT) run --fix

test:
	go test -race ./...

build:
	go build -o vuln-list-update .
