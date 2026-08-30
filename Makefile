.PHONY: build test clean cross install-local run-daemon vet lint help shim shim-linux e2e shim-ebpf

# ─── config ────────────────────────────────────────────────
GO          ?= go
BIN         := bin
DIST        := dist
VERSION     := $(shell git describe --tags --dirty --always 2>/dev/null || echo 0.1.0-pre)
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -ldflags "\
	-s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(BUILD_DATE)"

DAEMON := $(BIN)/oknekd
CLI    := $(BIN)/oknek

# Always re-run go build for the binaries (go's own cache keeps it fast);
# otherwise make treats the existing files as up-to-date and ships stale binaries.
.PHONY: $(DAEMON) $(CLI)

# ─── targets ───────────────────────────────────────────────
help:
	@echo "oknek targets:"
	@echo "  build         build oknekd + oknek for current host  →  $(BIN)/"
	@echo "  test          run unit tests"
	@echo "  vet           go vet ./..."
	@echo "  lint          golangci-lint run (if installed)"
	@echo "  cross         cross-compile to linux/amd64, linux/arm64, darwin/amd64, darwin/arm64  →  $(DIST)/"
	@echo "  install-local sudo install oknekd + oknek to /usr/local/bin"
	@echo "  run-daemon    run oknekd in foreground for dev (no systemd)"
	@echo "  clean         remove $(BIN)/ and $(DIST)/"

build: $(DAEMON) $(CLI)

$(DAEMON):
	@mkdir -p $(BIN)
	$(GO) build $(LDFLAGS) -o $(DAEMON) ./cmd/oknekd

$(CLI):
	@mkdir -p $(BIN)
	$(GO) build $(LDFLAGS) -o $(CLI) ./cmd/oknek

test:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed; skipping"; \
	fi

cross:
	@mkdir -p $(DIST)
	GOOS=linux  GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(DIST)/oknekd-linux-amd64  ./cmd/oknekd
	GOOS=linux  GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(DIST)/oknek-linux-amd64   ./cmd/oknek
	GOOS=linux  GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(DIST)/oknekd-linux-arm64  ./cmd/oknekd
	GOOS=linux  GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(DIST)/oknek-linux-arm64   ./cmd/oknek
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(DIST)/oknekd-darwin-amd64 ./cmd/oknekd
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(DIST)/oknek-darwin-amd64  ./cmd/oknek
	GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(DIST)/oknekd-darwin-arm64 ./cmd/oknekd
	GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(DIST)/oknek-darwin-arm64  ./cmd/oknek
	@echo "$(DIST)/ built. SHA-256:"
	@cd $(DIST) && shasum -a 256 * 2>/dev/null || sha256sum *

install-local: build
	sudo install -m 755 $(DAEMON) /usr/local/bin/
	sudo install -m 755 $(CLI)    /usr/local/bin/
	@echo "installed to /usr/local/bin/"

run-daemon: $(DAEMON)
	@echo "running oknekd in foreground (Ctrl+C to stop)"
	./$(DAEMON)

clean:
	rm -rf $(BIN) $(DIST)
	@echo "cleaned $(BIN)/ and $(DIST)/"

bundle: ## Assemble a concierge install bundle: make bundle KEY=okik_xxx ARTIFACTS=dist OUT=bundle
	@sh scripts/make-bundle.sh "$(KEY)" "$(ARTIFACTS)" "$(OUT)"

# ─── interposition shim (C) ────────────────────────────────
SHIM_SRC := internal/hooks/preload/oknek_preload.c
ifeq ($(shell uname),Darwin)
SHIM_OUT := $(BIN)/liboknek_preload.dylib
SHIM_LDL :=
else
SHIM_OUT := $(BIN)/liboknek_preload.so
SHIM_LDL := -ldl
endif

shim:
	@mkdir -p $(BIN)
	cc -shared -fPIC -O2 -Wall -o $(SHIM_OUT) $(SHIM_SRC) $(SHIM_LDL)
	@echo "built $(SHIM_OUT)"

shim-linux:
	@mkdir -p $(DIST)
	cc -shared -fPIC -O2 -Wall -o $(DIST)/liboknek_preload.so $(SHIM_SRC) -ldl
	@echo "built $(DIST)/liboknek_preload.so"

e2e: build shim
	bash internal/hooks/preload/e2e.sh

# ─── eBPF BPF-LSM object (kernel-grade R3 enforcement) ─────
# MUST run on a Linux box with clang + bpftool (Apple clang cannot target BPF).
# Commit the resulting oknek_lsm.o so the macOS cross-build can go:embed it.
EBPF_DIR := internal/hooks/ebpf
shim-ebpf:
	cd $(EBPF_DIR) && bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h && \
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -I/usr/include -c oknek_lsm.c -o oknek_lsm.o
	@echo "built $(EBPF_DIR)/oknek_lsm.o — commit it for the macOS cross-build"
