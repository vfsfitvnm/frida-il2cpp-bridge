MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

UNITY_DIR := test/unity
UNITY_VERSIONS := $(notdir $(realpath $(wildcard $(UNITY_DIR)/*/.)))

IMAGE_TAG := frida-il2cpp-bridge-playground:$(UNITY_VERSION)

dist: node_modules $(shell find lib) tsconfig.json
	@ npm exec tspc
	@ touch -m "$@"

node_modules:
	@ npm i
	@ touch -m "$@"

clean:
	@ rm -rf dist
	@ rm -rf test/agent/dist

assembly: .check_UNITY_VERSION
	@ make -C "$(UNITY_DIR)/$(UNITY_VERSION)/" assembly

image: .check_UNITY_VERSION
	@ docker build --platform linux/amd64 --build-arg UNITY_VERSION=$(UNITY_VERSION) -t $(IMAGE_TAG) test

test: dist test/agent/dist test/build/host
	@ test/run

testd: dist test/agent/dist
	@ export DOCKER_HOST=`docker context inspect --format '{{.Endpoints.docker.Host}}'`; test/run

test/agent/dist: node_modules $(shell find test/agent/src) test/agent/tsconfig.json
	@ npm exec tspc -- -p test/agent
	@ touch -m "$@"

test/build/host: test/src/host.c
	@ mkdir -p build
	@ clang -o "$(@)" "$<"

.DEFAULT_GOAL := dist
.PHONY: clean image assembly test testd .check_UNITY_VERSION

.check_UNITY_VERSION:
ifndef UNITY_VERSION
	$(error UNITY_VERSION is not set - possible values are $(UNITY_VERSIONS))
endif
ifeq ($(filter $(UNITY_VERSION),$(UNITY_VERSIONS)),)
	$(error UNITY_VERSION $(UNITY_VERSION) must be one of $(UNITY_VERSIONS))
endif
