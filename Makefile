APP_NAME := plug-registry
CMD_PATH := ./cmd/server
BUILD_DIR := bin

LDFLAGS := -s -w
GOFLAGS := -trimpath
TAGS :=

GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

GOAMD64 ?= v3

.PHONY: build build-redis build-postgres build-redis-postgres clean

# Normal build with memory cache and sqlite
build:
	@echo "Building $(APP_NAME) for $(GOOS)/$(GOARCH)"
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOAMD64=$(GOAMD64) \
	go build $(GOFLAGS) \
	-tags=r2_storage \
	-ldflags "$(LDFLAGS)" \
	-o $(BUILD_DIR)/$(APP_NAME) -v \
	$(CMD_PATH)

# Build with redis cache
build-redis:
	@echo "Building with Redis"
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOAMD64=$(GOAMD64) \
	go build $(GOFLAGS) \
	-tags "cache_redis" \
	-ldflags "$(LDFLAGS)" \
	-o $(BUILD_DIR)/$(APP_NAME)-redis \
	$(CMD_PATH)

# Build with postgres db
build-postgres:
	@echo "Building with Postgres"
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOAMD64=$(GOAMD64) \
	go build $(GOFLAGS) \
	-tags "db_postgres" \
	-ldflags "$(LDFLAGS)" \
	-o $(BUILD_DIR)/$(APP_NAME)-postgres \
	$(CMD_PATH)

# Build with redis cache and postgres db
build-redis-postgres:
	@echo "Building with Redis + Postgres"
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOAMD64=$(GOAMD64) \
	go build $(GOFLAGS) \
	-tags "cache_redis db_postgres" \
	-ldflags "$(LDFLAGS)" \
	-o $(BUILD_DIR)/$(APP_NAME)-redis-postgres \
	$(CMD_PATH)

fmt:
	go fmt ./...

test:
	go test -race ./... -v -short

clean:
	rm -rf $(BUILD_DIR)
