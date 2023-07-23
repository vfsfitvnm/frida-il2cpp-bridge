VER_GTE = $(shell printf '%s\n' "$2" "$1" | sort -C -V && echo YES || echo NO)

MAKEFLAGS += --no-builtin-rules

THIS_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
ROOT_DIR := $(shell realpath $(THIS_DIR)/../..)
UNITY_VERSION := $(shell basename $(THIS_DIR))
BUILD_DIR = $(ROOT_DIR)/build/$(UNITY_VERSION)
EDITOR_DIR = $(THIS_DIR)/Editor

MONO_DIR = $(EDITOR_DIR)/Data/Mono
MONOBL_DIR = $(EDITOR_DIR)/Data/MonoBleedingEdge
IL2CPP_DIR = $(EDITOR_DIR)/Data/il2cpp

MONO := $(MAYBE_STRACE) $(MONOBL_DIR)/bin/mono
MCS := $(MONO) $(MONOBL_DIR)/lib/mono/4.5/mcs.exe

LINKER_DESCRIPTORS_DIR := $(IL2CPP_DIR)/LinkerDescriptors

ifeq "$(call VER_GTE,$(UNITY_VERSION),2019.1.0f1)" "YES"
GENERATED_CPP_FILENAME := %
else
GENERATED_CPP_FILENAME := Bulk_%_0
endif

ASSEMBLY_TARGET := $(BUILD_DIR)/out/%.so
CPP_TARGET := $(BUILD_DIR)/cpp/$(GENERATED_CPP_FILENAME).cpp
LINKED_DLL_TARGET := $(BUILD_DIR)/linked/%.dll
DLL_TARGET := $(BUILD_DIR)/dll/%.dll
CS_SRC := $(ROOT_DIR)/test/%.cs

$(DLL_TARGET): $(CS_SRC) $(EDITOR_DIR) $(BUILD_DIR)
	@ echo "[$(UNITY_VERSION)] Compiling $(<F)"
	@ mkdir -p $(@D)
	@ $(MCS) \
		-target:library \
		-nologo \
		-noconfig \
		-unsafe \
		-out:"$@" \
		"$<"

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