.PHONY: tidy lint test build up down

tidy:
	go mod tidy

lint:
	golangci-lint run

test:
	go test -race -v ./...

build:
	go build ./...

up:
	docker compose up -d redis

down:
	docker compose down
