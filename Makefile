.PHONY: test vet build run-server

test:
	go test ./...

vet:
	go vet ./...

build:
	go build ./cmd/atc-server ./cmd/atc-agent ./cmd/atc

run-server:
	go run ./cmd/atc-server
