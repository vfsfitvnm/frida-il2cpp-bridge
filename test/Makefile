MAKEFLAGS += --no-builtin-rules

UNITY_DIRS = $(notdir $(realpath $(wildcard */)))

ASSEMBLY_TARGETS = $(addprefix assembly/,$(UNITY_DIRS))
ALL_TARGETS = $(addprefix all/,$(UNITY_DIRS))

.SECONDEXPANSION:

help:
	@ echo $(HOST_TARGETS)
	@ echo "Please read the source code"

$(ALL_TARGETS): $$(addsuffix assembly,$$(dir $$@));

host: host.c
	@ gcc -o "$(@)" "$<"

test: host
	node --test index.js

$(ASSEMBLY_TARGETS):
	@ make -C "./$(@F)" assembly

.DEFAULT_GOAL := help

.PHONY: help test $(ALL_TARGETS) $(ASSEMBLY_TARGETS)

.SUFFIXES:

