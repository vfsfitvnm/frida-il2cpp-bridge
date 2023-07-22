GENERATED_CPP_FILENAME := Bulk_%_0

include ../common.mk

mono := "$(EDITOR_DIR)/Data/Mono/bin/mono"
mono_lib := $(EDITOR_DIR)/Data/Mono/lib/mono/unity
mono_be := "$(EDITOR_DIR)/Data/MonoBleedingEdge/bin/mono"
il2cpp := $(mono_be) "$(EDITOR_DIR)/Data/il2cpp/build/il2cpp.exe"

export TERM = xterm

$(ASSEMBLY_TARGET): $(CPP_TARGET)
	@ echo "[$(UNITY_VERSION)] Compiling $(<F)"
	@ $(MAYBE_STRACE) $(il2cpp) \
		--generatedcppdir="$(<D)" \
		--compile-cpp \
		--libil2cpp-static \
		--configuration=Release \
		--platform=Linux \
		--architecture=x64 \
		--outputpath="$@" \
		--cachedirectory="$(@D)/.."
	@ strip "$@"

$(CPP_TARGET): $(LINKED_DLL_TARGET)
	@ echo "[$(UNITY_VERSION)] Generating $(@F)"
	@ $(MAYBE_STRACE) $(il2cpp) \
		--assembly="$^" \
		--convert-to-cpp \
		--emit-null-checks \
		--enable-array-bounds-check \
		--copy-level=None \
		--generatedcppdir="$(@D)"

$(LINKED_DLL_TARGET): export MONO_PATH=$(mono_lib)
$(LINKED_DLL_TARGET): $(DLL_TARGET)
	@ echo "[$(UNITY_VERSION)] Linking $(<F)"
	@ $(MAYBE_STRACE) $(mono) \
		"$(EDITOR_DIR)/Data/Tools/UnusedBytecodeStripper.exe" \
		-l none \
		-c link \
		-b false \
		-x "$(EDITOR_DIR)/Data/Tools/link.xml" \
		-out "$(@D)" \
		-a "$(mono_lib)/mscorlib.dll" \
		-a "$<"

$(DLL_TARGET): export MONO_PATH=$(mono_lib)
$(DLL_TARGET): $(CS_SRC) $(EDITOR_DIR) $(BUILD_DIR) 
	@ echo "[$(UNITY_VERSION)] Compiling $(<F)"
	@ mkdir -p $(@D)
	@ $(MAYBE_STRACE) $(mono) \
		"$(mono_lib)/smcs.exe" \
		-target:library \
		-out:"$@" \
		"$<"

$(EDITOR_DIR):
	@ echo "[$(UNITY_VERSION)] Downloading editor..."
	@ curl -L -s -A "" --fail "http://download.unity3d.com/download_unity/linux/unity-editor-5.3.5f1+20160525_amd64.deb" -o editor.deb

	@ echo "[$(UNITY_VERSION)] Extracting editor..."
	@ ar x editor.deb
	@ tar -xf data.tar.gz --strip-components=3 --exclude="usr*" --exclude="opt/Unity/MonoDevelop*"

	@ echo "[$(UNITY_VERSION)] Cleanup..."
	@ ar t editor.deb | xargs rm
	@ rm editor.deb
	@ touch -m Editor
