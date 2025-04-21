MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

UNITY_DIRS := $(wildcard unity/*/)

dist: node_modules $(shell find src) tsconfig.json
	@ ./node_modules/.bin/tspc
	@ touch -m "$@"

node_modules:
	@ npm i
	@ touch -m "$@"

test: dist test/agent/dist build/host
	@ python3 test/main.py

test/agent/dist: node_modules $(shell find test/agent/src) test/agent/tsconfig.json
	@ ./node_modules/.bin/tspc -p test/agent
	@ touch -m "$@"

build/host: test/host.c
	@ mkdir -p build
	@ gcc -o "$(@)" "$<"

$(UNITY_DIRS):
	make -C "$@" assembly

assembly: $(UNITY_DIRS);

clean:
	@ rm -rf dist
	@ rm -rf test/agent/dist

.DEFAULT_GOAL := dist
.PHONY: clean test assembly $(UNITY_DIRS)
