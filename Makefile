MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

UNITY_DIR := test/unity
UNITY_VERSIONS := $(notdir $(realpath $(wildcard $(UNITY_DIR)/*/.)))

IMAGE_TAG := frida-il2cpp-bridge-playground:$(UNITY_VERSION)

help:	## Show this message
	@ egrep -h '\s##\s' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m  %-30s\033[0m %s\n", $$1, $$2}'
	@ echo "  \033[3m\033[35mUnity versions for testing\033[0m     $(shell tr ' ' '\n' <<< "$(UNITY_VERSIONS)" | sort -V)"

dist: node_modules $(shell find lib) tsconfig.json	## Run TypeScript compiler to emit a bundled JavaScript file, map and typings
	@ npm exec tspc
	@ touch -m "$@"

node_modules:
	@ npm i
	@ touch -m "$@"

clean:	## Delete files created by TypeScript compiler
	@ rm -rf dist
	@ rm -rf test/agent/dist

assembly: .check_UNITY_VERSION	## (test) Create a GameAssembly.so using the given UNITY_VERSION (Linux only)
	@ make -C "$(UNITY_DIR)/$(UNITY_VERSION)/" assembly

image: .check_UNITY_VERSION	## (test) Build Docker image having a GameAssembly.so created using the given UNITY_VERSION
	@ docker build --platform linux/amd64 --build-arg UNITY_VERSION=$(UNITY_VERSION) -t $(IMAGE_TAG) test

test: dist test/agent/dist test/build/host	## (test) Run tests on each local GameAssembly.so (Linux only)
	@ test/run

testd: dist test/agent/dist	## (test) Run tests on each dockerized GameAssembly.so
	@ export DOCKER_HOST=`docker context inspect --format '{{.Endpoints.docker.Host}}'`; test/run

test/agent/dist: node_modules $(shell find test/agent/src) test/agent/tsconfig.json
	@ npm exec tspc -- -p test/agent
	@ touch -m "$@"

test/build/host: test/src/host.c
	@ mkdir -p build
	@ clang -o "$(@)" "$<"

.DEFAULT_GOAL := help
.PHONY: clean image assembly test testd .check_UNITY_VERSION

.check_UNITY_VERSION:
ifndef UNITY_VERSION
	$(error UNITY_VERSION is not set - possible values are $(UNITY_VERSIONS))
endif
ifeq ($(filter $(UNITY_VERSION),$(UNITY_VERSIONS)),)
	$(error UNITY_VERSION $(UNITY_VERSION) must be one of $(UNITY_VERSIONS))
endif
