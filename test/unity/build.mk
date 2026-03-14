include ../common.mk

MONO_DIR = $(EDITOR_DIR)/Data/Mono
MONOBL_DIR = $(EDITOR_DIR)/Data/MonoBleedingEdge
IL2CPP_DIR = $(EDITOR_DIR)/Data/il2cpp

MONO := $(MONOBL_DIR)/bin/mono
MCS := $(MONO) $(MONOBL_DIR)/lib/mono/4.5/mcs.exe

LINKER_DESCRIPTORS_DIR := $(IL2CPP_DIR)/LinkerDescriptors

ifeq "$(call VER_GTE,$(UNITY_VERSION),2019.1.0f1)" "YES"
GENERATED_CPP_FILENAME := %
else
GENERATED_CPP_FILENAME := Bulk_%_0
endif

BUILD_DIR = $(ROOT_DIR)/build/$(UNITY_VERSION)

ASSEMBLY_TARGET := $(BUILD_DIR)/out/%.so
CPP_TARGET := $(BUILD_DIR)/cpp/$(GENERATED_CPP_FILENAME).cpp
LINKED_DLL_TARGET := $(BUILD_DIR)/linked/%.dll
DLL_TARGET := $(BUILD_DIR)/dll/%.dll
CS_SRC := $(ROOT_DIR)/src/%.cs

$(ASSEMBLY_TARGET): $(CPP_TARGET)
	@ $(ECHO) Compiling $(<F)
	$(ASSEMBLY_TARGET_CMD)
	@ strip "$@"

$(CPP_TARGET): $(LINKED_DLL_TARGET)
	@ $(ECHO) Generating $(@F)
	$(CPP_TARGET_CMD)

$(LINKED_DLL_TARGET): $(DLL_TARGET)
	@ $(ECHO) Linking $(<F)
	$(LINKED_DLL_TARGET_CMD)
	@ touch "$@"

$(DLL_TARGET): $(CS_SRC) $(EDITOR_DIR) $(BUILD_DIR)
	@ $(ECHO) Compiling $(<F)
	@ mkdir -p "$(@D)"
	$(DLL_TARGET_CMD)

$(BUILD_DIR):
	@ mkdir -p "$@"

DLL_TARGET_CMD ?= $(MCS) \
	-target:library \
	-nologo \
	-noconfig \
	-unsafe \
	-out:"$@" \
	"$<"

assembly: $(BUILD_DIR)/out/GameAssembly.so

clean:
	@ rm -rf "$(BUILD_DIR)"

.PHONY: assembly clean