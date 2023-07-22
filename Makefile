MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

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

clean:
	@ rm -r dist

.DEFAULT_GOAL := dist
.PHONY: clean test
