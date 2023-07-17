THIS_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
ROOT_DIR := $(shell realpath $(THIS_DIR)/../..)
UNITY_VERSION := $(shell basename $(THIS_DIR))
BUILD_DIR = $(ROOT_DIR)/build/$(UNITY_VERSION)

mono := "$(THIS_DIR)/Editor/Data/Mono/bin/mono"
mono_lib := $(THIS_DIR)/Editor/Data/Mono/lib/mono/unity
mono_be := "$(THIS_DIR)/Editor/Data/MonoBleedingEdge/bin/mono"
il2cpp := $(mono_be) "$(THIS_DIR)/Editor/Data/il2cpp/build/il2cpp.exe"

export TERM = xterm

assembly: $(THIS_DIR)/Editor $(BUILD_DIR) $(BUILD_DIR)/out/GameAssembly.so

$(BUILD_DIR)/out/%.so: $(BUILD_DIR)/cpp/Bulk_%_0.cpp
	@ echo "[$(UNITY_VERSION)] Compiling $(<F)"
	@ $(il2cpp) \
		--generatedcppdir="$(<D)" \
		--compile-cpp \
		--libil2cpp-static \
		--configuration=Release \
		--platform=Linux \
		--architecture=x64 \
		--outputpath="$@" \
		--cachedirectory="$(@D)/.."
	@ strip "$@"

$(BUILD_DIR)/cpp/Bulk_%_0.cpp: $(BUILD_DIR)/linked/%.dll
	@ echo "[$(UNITY_VERSION)] Generating $(@F)"
	@ $(il2cpp) \
		--assembly="$^" \
		--convert-to-cpp \
		--emit-null-checks \
		--enable-array-bounds-check \
		--copy-level=None \
		--generatedcppdir="$(@D)"

$(BUILD_DIR)/linked/%.dll: export MONO_PATH=$(mono_lib)
$(BUILD_DIR)/linked/%.dll: $(BUILD_DIR)/dll/%.dll
	@ echo "[$(UNITY_VERSION)] Linking $(<F)"
	@ $(mono) \
		"$(THIS_DIR)/Editor/Data/Tools/UnusedBytecodeStripper.exe" \
		-l none \
		-c link \
		-b false \
		-x "$(THIS_DIR)/Editor/Data/Tools/link.xml" \
		-out "$(@D)" \
		-a "$(mono_lib)/mscorlib.dll" \
		-a "$<"

$(BUILD_DIR)/dll/%.dll: export MONO_PATH=$(mono_lib)
$(BUILD_DIR)/dll/%.dll:
	@ echo "[$(UNITY_VERSION)] Compiling $*.cs"
	@ mkdir -p $(@D)
	@ $(mono) \
		"$(mono_lib)/smcs.exe" \
		-target:library \
		-out:"$@" \
		"$(ROOT_DIR)/test/$*.cs"

$(BUILD_DIR):
	mkdir -p $@

$(THIS_DIR)/Editor:
	@ echo "[$(UNITY_VERSION)] Downloading editor..."
	@ curl -L -s -A "" --fail "http://download.unity3d.com/download_unity/linux/unity-editor-5.3.5f1+20160525_amd64.deb" -o editor.deb

	@ echo "[$(UNITY_VERSION)] Extracting editor..."
	@ ar x editor.deb
	@ tar -xf data.tar.gz --strip-components=3 --files-from=includelist.txt

	@ echo "[$(UNITY_VERSION)] Cleanup..."
	@ ar t editor.deb | xargs rm
	@ rm editor.deb
	@ touch -m Editor

clean:
	@ rm -r $(BUILD_DIR)

.PHONY: assembly clean

.SECONDARY:
