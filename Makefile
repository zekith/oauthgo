.PHONY: tidy lint test build

tidy:
	go mod tidy

lint:
	golangci-lint run

test:
	go test -race -v ./...

build:
	go build ./...