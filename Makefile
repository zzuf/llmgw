.PHONY: build check test race

build:
	go build -trimpath -o bin/llmgw ./cmd/llmgw

check:
	sh scripts/check.sh

test:
	go test ./...

race:
	go test -race ./...
