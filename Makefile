MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

export UNITY_VERSIONS := 5.3.5f1 2018.3.0f1 2019.3.0f1 2021.2.0f1

DEBUG_TARGETS = $(addprefix debug/,$(UNITY_VERSIONS))

dist: node_modules $(shell find src) tsconfig.json
	@ ./node_modules/.bin/tspc
	@ touch -m dist

node_modules:
	@ npm i
	@ touch -m node_modules

test: test/index.js test/test.js dist test/host
	@ node --test "$<"

test/host: test/host.c
	@ gcc -o "$(@)" "$<"

clean:
	@ rm -r dist

.DEFAULT_GOAL := dist
.PHONY: clean test $(DEBUG_TARGETS)
