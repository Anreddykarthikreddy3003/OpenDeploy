# OpenDeploy build entry points.
GO        ?= go
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X github.com/anreddykarthikreddy3003/opendeploy/internal/daemon.Version=$(VERSION) -X github.com/anreddykarthikreddy3003/opendeploy/internal/cli.Version=$(VERSION) -X main.version=$(VERSION)
BIN       := bin
CMDS      := $(notdir $(wildcard cmd/*)) relay-server

.PHONY: all build web test test-race vet lint fmt adversarial e2e clean

all: build

web:
	cd web && npm ci && npm run build

build:
	@mkdir -p $(BIN)
	@for c in $(notdir $(wildcard cmd/*)); do \
		echo "build $$c"; CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/$$c ./cmd/$$c || exit 1; \
	done
	@if [ -d relay-server/cmd/relay-server ]; then CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/relay-server ./relay-server/cmd/relay-server; fi

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w $$(git ls-files '*.go')

lint:
	golangci-lint run ./...

# Adversarial suite (ST-01..ST-12). Needs a Linux host with the data plane
# installed; tests skip (and report capability-blocked) where the host
# cannot enforce a control rather than silently passing.
adversarial:
	$(GO) test -tags adversarial -count=1 -v ./tests/adversarial/...

e2e:
	$(GO) test -tags e2e -count=1 -v ./tests/e2e/...

clean:
	rm -rf $(BIN) dist
