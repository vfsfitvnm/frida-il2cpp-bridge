MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

UNITY_DIRS := $(wildcard unity/*/)

dist: node_modules $(shell find src) tsconfig.json
	@ ./node_modules/.bin/tspc
	@ touch -m dist

node_modules:
	@ npm i
	@ touch -m node_modules

test: test/index.js test/agent.js dist build/host
	@ node "$<"

build/host: test/host.c
	@ mkdir -p build
	@ gcc -o "$(@)" "$<"

$(UNITY_DIRS):
	make -C "$@" assembly

assembly: $(UNITY_DIRS);

clean:
	@ rm -r dist

.DEFAULT_GOAL := dist
.PHONY: clean test assembly $(UNITY_DIRS)
