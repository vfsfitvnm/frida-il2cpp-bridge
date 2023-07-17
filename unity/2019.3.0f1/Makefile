THIS_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
ROOT_DIR := $(shell realpath $(THIS_DIR)/../..)
UNITY_VERSION := $(shell basename $(THIS_DIR))
BUILD_DIR = $(ROOT_DIR)/build/$(UNITY_VERSION)

mono_dir := $(THIS_DIR)/Editor/Data/MonoBleedingEdge
il2cpp_dir := $(THIS_DIR)/Editor/Data/il2cpp/build/deploy/net471

export TERM = xterm

assembly: $(BUILD_DIR) $(BUILD_DIR)/out/GameAssembly.so

$(BUILD_DIR)/out/%.so: $(BUILD_DIR)/cpp/%.cpp
	@ echo "[$(UNITY_VERSION)] Compiling $(<F)"
	"$(mono_dir)/bin-linux64/mono" \
		"$(il2cpp_dir)/il2cpp.exe" \
		--generatedcppdir="$(<D)" \
		--compile-cpp \
		--libil2cpp-static \
		--configuration=Release \
		--platform=Linux \
		--architecture=x64 \
		--dotnetprofile=unityaot \
		--outputpath="$@" \
		--cachedirectory="$(@D)/../buildstate"
	@ strip "$@"

$(BUILD_DIR)/cpp/%.cpp: $(BUILD_DIR)/linked/%.dll
	@ echo "[$(UNITY_VERSION)] Generating $(@F)"
	@ "$(mono_dir)/bin-linux64/mono" \
		"$(il2cpp_dir)/il2cpp.exe" \
		--directory="$(<D)" \
		--convert-to-cpp \
		--emit-null-checks \
		--enable-array-bounds-check \
		--dotnetprofile="unityaot" \
		--copy-level=None \
		--generatedcppdir="$(@D)"

$(BUILD_DIR)/linked/%.dll: $(BUILD_DIR)/dll/%.dll
	@ echo "[$(UNITY_VERSION)] Linking $(<F)"
	@ "$(mono_dir)/bin-linux64/mono" \
		"$(il2cpp_dir)/UnityLinker.exe" \
		--include-assembly="$<,$(mono_dir)/lib/mono/unityaot/mscorlib.dll" \
		--i18n=none \
		--core-action=link \
		--dotnetruntime=il2cpp \
		--dotnetprofile=unityaot \
		--use-editor-options \
		--out="$(@D)"

$(BUILD_DIR)/dll/%.dll:
	@ echo "[$(UNITY_VERSION)] Compiling $*.cs"
	@ mkdir -p $(@D)
	@ "$(mono_dir)/bin-linux64/mono" \
		"$(mono_dir)/lib/mono/4.5/csc.exe" \
		-target:library \
		-nologo \
		-unsafe \
		-out:"$@" \
		"$(ROOT_DIR)/test/$*.cs"

$(BUILD_DIR):
	@ mkdir -p "$@"

clean:
	@ rm -r "$(BUILD_DIR)"

.PHONY: assembly clean

.SECONDARY:
