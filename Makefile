VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -X main.version=$(VERSION) -w -s
BINARY  := lw
CMD     := ./cmd/lw

.PHONY: build build-all web test lint setup clean

## build: build lw for the current platform
build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

## build-all: cross-compile release binaries into dist/
build-all:
	mkdir -p dist
	GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/lw-linux-amd64   $(CMD)
	GOOS=linux  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/lw-linux-arm64   $(CMD)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/lw-darwin-amd64  $(CMD)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/lw-darwin-arm64  $(CMD)

## web: build the TypeScript web viewer into web/dist/
web:
	cd web && npm ci && npm run build

## test: run the full test suite with race detector
test:
	go test -race ./...

## lint: run all linters (Go + TypeScript)
lint:
	golangci-lint run
	cd web && npx tsc --noEmit

## setup: install pre-commit hook and required tools
setup:
	@echo "Installing pre-commit hook..."
	cp scripts/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "Installing golangci-lint..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Installing web dependencies..."
	cd web && npm ci
	@echo "Setup complete."

## clean: remove build artifacts
clean:
	rm -f $(BINARY)
	rm -rf dist/
	rm -rf web/dist/

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
