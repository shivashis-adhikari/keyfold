VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test short lint bench caddy demo clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/keyfold ./cmd/keyfold
	go build -o bin/fakeshop ./cmd/fakeshop

test:
	go test -race ./...

# skips the tests that probe the fake shop or start caddy/nginx
short:
	go test -short ./...

lint:
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...

bench:
	go test -run xxx -bench . -benchmem ./internal/cache ./internal/logs ./internal/plan

# caddy with the cache handler, for the caddy tests and the demo.
# KEYFOLD_CADDY=bin/caddy make test
caddy:
	go run github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.7 build --with github.com/caddyserver/cache-handler --output bin/caddy

demo: build
	./scripts/demo.sh

clean:
	rm -rf bin demo
