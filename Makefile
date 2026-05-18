.PHONY: build test lint smoke scan-self clean

GO ?= go
BIN := bin/wfguard

build:
	$(GO) build -o $(BIN) ./cmd/wfguard

test:
	$(GO) test ./... -race -count=1

lint:
	$(GO) vet ./...
	$(GO) fmt ./...

smoke: build
	./$(BIN) smoke

# Audit this repo's own workflows once it has any.
scan-self: build
	./$(BIN) scan .

clean:
	rm -rf bin/
