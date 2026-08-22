# dualnet — common developer tasks. Run `make` (or `make help`) for the list.
#
# Overridable variables (make <target> VAR=value):
#   NETWORK      whole-mesh schema compiled/simulated               (docs/examples/network.yaml)
#   CONFIG_DIR   output dir for `make compile`                      (configs)
#   IMAGE        runtime Docker image tag                           (arash16/dualnet:latest)
#   ARGS         extra flags forwarded to run / sim                 (empty)

GO         ?= go
BIN        := dualnet
PKG        := ./...
DIST       := dist
NETWORK    ?= docs/examples/network.yaml
CONFIG_DIR ?= configs
IMAGE      ?= arash16/dualnet:latest
LDFLAGS    := -s -w

.DEFAULT_GOAL := help

.PHONY: help host-build build install run compile sim deploy logs fmt fmt-check vet lint test test-race \
        test-e2e cover bench tidy check check-all docker docker-push clean clean-all

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*##"}{printf "  \033[36m%-13s\033[0m%s\n", $$1, $$2}'

## --- build & run -----------------------------------------------------------

host-build: ## Build the dualnet binary for THIS machine (local dev / running a node here)
	$(GO) build -ldflags='$(LDFLAGS)' -o $(BIN) .

install: ## Install the dualnet binary into GOBIN
	$(GO) install .

run: ## Run a node; pass ARGS (e.g. make run ARGS="-config configs/router.yaml -debug-tun")
	$(GO) run . $(ARGS)

compile: ## Compile NETWORK into per-node configs under CONFIG_DIR
	$(GO) run . compile -network $(NETWORK) -out $(CONFIG_DIR)

sim: ## Run the netsim Docker simulation for NETWORK; pass ARGS (e.g. ARGS="-only failover -keep")
	$(GO) run ./cmd/netsim -network $(NETWORK) $(ARGS)

## --- release: compile -> build -> deploy -----------------------------------

build: compile ## Cross-compile every release binary + image via the generated build.sh
	$(CONFIG_DIR)/build.sh

deploy: build ## Deploy the built mesh via the generated deploy.sh (needs DUALNET_PSK); ARGS="router vps"
	$(CONFIG_DIR)/deploy.sh $(ARGS)

logs: ## Fetch each ssh node's stats log via the generated deploy.sh into $(CONFIG_DIR)/logs/
	$(CONFIG_DIR)/deploy.sh --logs $(ARGS)

## --- quality ---------------------------------------------------------------

fmt: ## Format all Go files (gofmt -s -w)
	gofmt -s -w .

fmt-check: ## Fail if any Go file needs gofmt
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "needs gofmt:"; echo "$$out"; exit 1; fi

vet: ## Run go vet
	$(GO) vet $(PKG)

lint: fmt-check vet ## gofmt check + go vet + staticcheck (if installed)
	@if command -v staticcheck >/dev/null 2>&1; then \
		echo "staticcheck $(PKG)"; staticcheck $(PKG); \
	else \
		echo "staticcheck not installed (go install honnef.co/go/tools/cmd/staticcheck@latest); skipping"; \
	fi

## --- tests -----------------------------------------------------------------

test: ## Run all unit tests
	$(GO) test $(PKG)

test-race: ## Run all tests with the race detector
	$(GO) test -race $(PKG)

test-e2e: ## Run the Docker-based end-to-end test (requires Docker)
	$(GO) test -tags e2e -count=1 ./test/e2e/...

cover: ## Run tests with coverage and print the total
	$(GO) test -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -func=coverage.out | tail -1

bench: ## Run benchmarks (cipher + packet hot path)
	$(GO) test -run '^$$' -bench=. -benchmem ./internal/cipher/ ./internal/node/

tidy: ## Tidy go.mod / go.sum
	$(GO) mod tidy

check: fmt-check vet lint test ## Full local gate: fmt-check + vet + lint + tests
check-all: check test-race test-e2e cover bench

## --- docker ----------------------------------------------------------------

docker: ## Build the runtime Docker image (IMAGE)
	docker build -t $(IMAGE) .

docker-push: docker ## Build + push the image
	docker push arash16/dualnet

## --- housekeeping ----------------------------------------------------------

clean: ## Remove build artifacts (binary, dist/, coverage)
	rm -f $(BIN) coverage.out
	rm -rf $(DIST)
	$(GO) clean

clean-all: clean ## Also remove generated configs/
	rm -rf $(CONFIG_DIR)
