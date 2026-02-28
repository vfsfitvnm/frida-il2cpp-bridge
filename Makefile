MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

UNITY_DIRS := $(wildcard unity/*/)

dist: node_modules $(shell find lib) tsconfig.json
	@ npm exec tspc
	@ touch -m "$@"

node_modules:
	@ npm i
	@ touch -m "$@"

test: dist test/agent/dist build/host
	@ python3 test/main.py

testd: dist test/agent/dist
	@ export DOCKER_HOST=`docker context inspect --format '{{.Endpoints.docker.Host}}'`; python3 test/main.py

test/agent/dist: node_modules $(shell find test/agent/src) test/agent/tsconfig.json
	@ npm exec tspc -- -p test/agent
	@ touch -m "$@"

build/host: test/host.c
	@ mkdir -p build
	@ clang -o "$(@)" "$<"

$(UNITY_DIRS):
	make -C "$@" assembly

assembly: $(UNITY_DIRS);

ifdef UNITY_VERSION
IMAGE_TAG := frida-il2cpp-bridge-playground:$(UNITY_VERSION)

image:
	@ docker build --platform linux/amd64 --build-arg UNITY_VERSION=$(UNITY_VERSION) -t $(IMAGE_TAG) .

.PHONY: image
endif

clean:
	@ rm -rf dist
	@ rm -rf test/agent/dist

.DEFAULT_GOAL := dist
.PHONY: clean test assembly $(UNITY_DIRS)
