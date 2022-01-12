BIN_NAME := encrypt-file-in-image
BIN_PATH := bin/$(BIN_NAME)
BUILD_FLAGS := -installsuffix "static"

.PHONY: all build clean deps

all: build

build:
	CGO_ENABLED=1 \
	GO111MODULE=on \
	GOARCH=amd64 \
	go build \
	$(BUILD_FLAGS) \
	-o $(BIN_PATH) \
	$$(find cmd/app/*.go)

deps:
	@echo Downloading go.mod dependencies && \
		go mod download
