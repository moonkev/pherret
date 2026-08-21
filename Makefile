# Makefile for pherret
#
# Common targets:
#   make build      - build the pherret binary for the current OS/arch
#   make test       - run the test suite
#   make vet        - run go vet
#   make fmt        - format all Go source files
#   make lint       - run golangci-lint (installed on demand if missing)
#   make clean      - remove build artifacts
#   make install    - install pherret into $GOPATH/bin (or GOBIN)
#   make run ARGS=  - build and run pherret, e.g. make run ARGS="list -r /tmp"
#   make cross      - build binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64
#   make ci         - run the same steps as CI (build + test)

MODULE      := github.com/moonkev/pherret
DIST        := dist
BINARY      ?= pherret
GO          ?= go

.PHONY: all
all: build

.PHONY: build
build:
	$(GO) build -o $(BINARY) .

.PHONY: test
test:
	$(GO) test -v ./...

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: lint
lint:
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "golangci-lint not found, installing..."; \
		$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest; \
	fi
	golangci-lint run ./...

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: clean
clean:
	rm -f $(BINARY)
	rm -rf $(DIST)

.PHONY: install
install:
	$(GO) install .

.PHONY: run
run: build
	./$(BINARY) $(ARGS)

.PHONY: ci
ci: build test

# Cross-compilation for release-style builds. CGo is required for the macOS
# (darwin) scan backend, so darwin targets are only built when running on
# macOS with the appropriate cross toolchain; otherwise they are skipped.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.PHONY: cross
cross: clean
	@mkdir -p $(DIST)
	@host_os=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	for platform in $(PLATFORMS); do \
	   os=$$(echo $$platform | cut -d/ -f1); \
	   arch=$$(echo $$platform | cut -d/ -f2); \
	   out=$(DIST)/$(BINARY)-$$os-$$arch; \
	   if [ "$$os" = "darwin" ] && [ "$$host_os" != "darwin" ]; then \
	      echo "[skip] not building for $$os/$$arch - requires macOS with the appropriate cross toolchain"; \
	      continue; \
	   fi; \
	   echo "Building $$out..."; \
	   GOOS=$$os GOARCH=$$arch CGO_ENABLED=$$( [ "$$os" = "darwin" ] && echo 1 || echo 0 ) \
	      $(GO) build -o $$out . || { echo "Build failed for $$os/$$arch"; exit 1; }; \
	done


