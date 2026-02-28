MAKEFLAGS += --no-builtin-rules

VER_GTE = $(shell printf '%s\n' "$2" "$1" | sort -C -V && echo YES || echo NO)

THIS_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
ROOT_DIR := $(shell realpath $(THIS_DIR)/../..)
UNITY_VERSION := $(shell basename $(THIS_DIR))
BUILD_DIR = $(ROOT_DIR)/build/$(UNITY_VERSION)
EDITOR_DIR = $(THIS_DIR)/Editor

ECHO := echo "$(UNITY_VERSION) ►"
CURL := curl -L -A "" --fail

.SECONDARY:
