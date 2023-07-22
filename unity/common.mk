MAKEFLAGS += --no-builtin-rules

THIS_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
ROOT_DIR := $(shell realpath $(THIS_DIR)/../..)
UNITY_VERSION := $(shell basename $(THIS_DIR))
BUILD_DIR = $(ROOT_DIR)/build/$(UNITY_VERSION)
EDITOR_DIR = $(THIS_DIR)/Editor

GENERATED_CPP_FILENAME ?= %

ASSEMBLY_TARGET := $(BUILD_DIR)/out/%.so
CPP_TARGET := $(BUILD_DIR)/cpp/$(GENERATED_CPP_FILENAME).cpp
LINKED_DLL_TARGET := $(BUILD_DIR)/linked/%.dll
DLL_TARGET := $(BUILD_DIR)/dll/%.dll

$(BUILD_DIR):
	@ mkdir -p "$@"

.PHONY: assembly
assembly: $(BUILD_DIR)/out/GameAssembly.so

# USED_FILE_LIST := $(BUILD_DIR)/filelist.txt
# .PHONY: minimalize
# minimalize: MAYBE_STRACE := strace -z -o "$(BUILD_DIR)/filelist.txt" -A -e trace=file
# minimalize: | clean assembly
# 	@ grep -oP '$(EDITOR_DIR)/[^"]+' "$(USED_FILE_LIST)" | sort -u | sed -E 's#/+#/#g' > "$(USED_FILE_LIST).sorted"
# 	@ find "$(EDITOR_DIR)" -type f -not -path "$(EDITOR_DIR)/Data/il2cpp/*" -print0 | grep -zFxvf "$(USED_FILE_LIST).sorted" | xargs -0 rm
# 	@ find "$(EDITOR_DIR)" -type d -empty -delete

.PHONY: clean
clean:
	@ rm -rf "$(BUILD_DIR)"

.SECONDARY:

.SUFFIXES:

assembly/5.3.5f1:
	@ make -C 5.3.5f1 assembly