BINARY     := ssync
BIN_DIR    := bin
MODULE     := github.com/user/ssync
BUILD_FLAGS := -trimpath

.PHONY: all build test test-short test-crypto test-internal test-cmd lint vet clean tidy

all: build

## build: compile the binary to ./bin/ssync
build:
	@mkdir -p $(BIN_DIR)
	go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY) .

## test: run the full test suite
test:
	go test ./... -count=1 -timeout 120s

## test-short: run tests, skipping integration tests
test-short:
	go test ./... -count=1 -short -timeout 60s

## test-crypto: run only the crypto package tests
test-crypto:
	go test ./internal/crypto/... -v -count=1

## test-internal: run all internal package tests
test-internal:
	go test ./internal/... -count=1 -timeout 120s

## test-cmd: run only the cmd package tests
test-cmd:
	go test ./cmd/... -v -count=1

## vet: run go vet
vet:
	go vet ./...

## lint: alias for vet
lint: vet

## tidy: tidy and verify go modules
tidy:
	go mod tidy
	go mod verify

## clean: remove build artifacts
clean:
	@rm -rf $(BIN_DIR)

## help: print this help message
help:
	@grep -E '^## ' Makefile | sed 's/^## /  /'
