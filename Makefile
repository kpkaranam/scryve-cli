# ============================================================================
# Scryve — Makefile
# ============================================================================
# Targets:
#   make build          — build native binary to bin/scryve
#   make build-all      — cross-compile for linux/darwin/windows × amd64/arm64
#   make test           — run all unit and integration tests
#   make lint           — run golangci-lint
#   make clean          — remove build artifacts
#   make fmt            — format source with gofmt / goimports
#   make vet            — run go vet
#   make check          — fmt + vet + lint + test (CI gate)
#   make install        — install binary to $(GOPATH)/bin or $(GOBIN)
#   make snapshot       — build a goreleaser snapshot (no publish)
# ============================================================================

# --------------------------------------------------------------------------- #
# Build metadata injected via -ldflags
# --------------------------------------------------------------------------- #
MODULE      := github.com/scryve/scryve
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE        ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS     := -s -w \
               -X $(MODULE)/cmd.Version=$(VERSION) \
               -X $(MODULE)/cmd.Commit=$(COMMIT) \
               -X $(MODULE)/cmd.Date=$(DATE)

# --------------------------------------------------------------------------- #
# Paths and tool locations
# --------------------------------------------------------------------------- #
BIN_DIR     := bin
BINARY      := $(BIN_DIR)/scryve
GOBIN       ?= $(shell go env GOPATH)/bin
GOLANGCI    ?= $(GOBIN)/golangci-lint

# --------------------------------------------------------------------------- #
# Cross-compilation targets
# Produces: bin/scryve-<OS>-<ARCH>[.exe]
# --------------------------------------------------------------------------- #
PLATFORMS := \
  linux/amd64 \
  linux/arm64 \
  darwin/amd64 \
  darwin/arm64 \
  windows/amd64 \
  windows/arm64

.PHONY: all build build-all test lint fmt vet check install clean snapshot help

all: check build

## build: Compile a native binary to bin/scryve
build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .
	@echo "Built: $(BINARY)  ($(VERSION), $(COMMIT))"

## build-all: Cross-compile for all supported platforms
build-all:
	@mkdir -p $(BIN_DIR)
	@for platform in $(PLATFORMS); do \
	  OS=$$(echo $$platform | cut -d/ -f1); \
	  ARCH=$$(echo $$platform | cut -d/ -f2); \
	  OUT=$(BIN_DIR)/scryve-$$OS-$$ARCH; \
	  if [ "$$OS" = "windows" ]; then OUT=$$OUT.exe; fi; \
	  echo "Building $$OUT ..."; \
	  CGO_ENABLED=0 GOOS=$$OS GOARCH=$$ARCH \
	    go build -trimpath -ldflags "$(LDFLAGS)" -o $$OUT . ; \
	done
	@echo "All binaries written to $(BIN_DIR)/"

## test: Run all tests with race detector and coverage
test:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	@echo "Coverage report: coverage.out"

## test-cover: Open coverage report in browser
test-cover: test
	go tool cover -html=coverage.out

## lint: Run golangci-lint (installs if missing)
lint: $(GOLANGCI)
	$(GOLANGCI) run ./...

$(GOLANGCI):
	@echo "Installing golangci-lint..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

## fmt: Format all Go source files
fmt:
	gofmt -s -w .
	@which goimports >/dev/null 2>&1 && goimports -w . || true

## vet: Run go vet
vet:
	go vet ./...

## check: Full pre-commit/CI gate (fmt + vet + lint + test)
check: fmt vet lint test

## install: Install scryve binary to GOPATH/bin
install:
	CGO_ENABLED=0 go install -trimpath -ldflags "$(LDFLAGS)" .
	@echo "Installed to $(GOBIN)/scryve"

## clean: Remove build artifacts and caches
clean:
	rm -rf $(BIN_DIR) coverage.out dist/
	go clean -testcache

## snapshot: Build a goreleaser snapshot (dry-run, no publish)
snapshot:
	goreleaser build --snapshot --clean

## help: Print this help message
help:
	@grep -E '^## ' Makefile | sed 's/## /  /' | column -t -s ':'
