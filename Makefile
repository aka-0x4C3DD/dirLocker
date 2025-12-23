.PHONY: all build build-core build-cli build-gui test clean check

BINARY_DIR := bin
EXTENSION := 
ifeq ($(OS),Windows_NT)
	EXTENSION := .exe
endif

all: build

build: build-core build-cli build-gui

build-core:
	cd vault-core && cargo build --release

build-cli:
	mkdir -p $(BINARY_DIR)
	go build -o $(BINARY_DIR)/dirlocker-cli$(EXTENSION) ./cmd/cli

build-gui:
	mkdir -p $(BINARY_DIR)
	go build -o $(BINARY_DIR)/dirlocker-gui$(EXTENSION) ./cmd/gui

test: test-go test-rust

test-go:
	go test ./pkg/... ./internal/... ./tests/...

test-rust:
	cd vault-core && cargo test

clean:
	rm -rf $(BINARY_DIR)
	cd vault-core && cargo clean

check:
	go vet ./...
	cd vault-core && cargo check
