.PHONY: build test fmt vet clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Cross-compile in a throwaway golang container — no host Go required.
# Matches the topology rule used by the agent build.
BUILDER := docker run --rm -v $(PWD):/src -v $(PWD)/bin:/out -w /src \
            -e GOOS -e GOARCH -e CGO_ENABLED=0 \
            golang:1.24-alpine sh -c

build:
	mkdir -p bin
	GOOS=linux GOARCH=amd64 $(BUILDER) \
	  'go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$(VERSION)" -o /out/kvmfleet-verify.linux-amd64 .'
	GOOS=linux GOARCH=arm64 $(BUILDER) \
	  'go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$(VERSION)" -o /out/kvmfleet-verify.linux-arm64 .'
	GOOS=darwin GOARCH=amd64 $(BUILDER) \
	  'go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$(VERSION)" -o /out/kvmfleet-verify.darwin-amd64 .'
	GOOS=darwin GOARCH=arm64 $(BUILDER) \
	  'go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$(VERSION)" -o /out/kvmfleet-verify.darwin-arm64 .'
	GOOS=windows GOARCH=amd64 $(BUILDER) \
	  'go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$(VERSION)" -o /out/kvmfleet-verify.windows-amd64.exe .'
	@echo "built ./bin/kvmfleet-verify.*  ($(VERSION))"

test:
	docker run --rm -v $(PWD):/src -w /src golang:1.24-alpine \
	  sh -c 'go test -v ./...'

fmt:
	docker run --rm -v $(PWD):/src -w /src golang:1.24-alpine gofmt -w .

vet:
	docker run --rm -v $(PWD):/src -w /src golang:1.24-alpine go vet ./...

clean:
	rm -rf bin
