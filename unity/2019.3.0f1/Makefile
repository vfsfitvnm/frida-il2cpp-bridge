include ../common.mk

mono_dir := $(EDITOR_DIR)/Data/MonoBleedingEdge
il2cpp_dir := $(EDITOR_DIR)/Data/il2cpp/build/deploy/net471

export TERM = xterm

$(ASSEMBLY_TARGET): $(CPP_TARGET)
	@ echo "[$(UNITY_VERSION)] Compiling2 $(<F)"
	@ $(MAYBE_STRACE) "$(mono_dir)/bin-linux64/mono" \
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

$(CPP_TARGET): $(LINKED_DLL_TARGET)
	@ echo "[$(UNITY_VERSION)] Generating $(@F)"
	@ $(MAYBE_STRACE) "$(mono_dir)/bin-linux64/mono" \
		"$(il2cpp_dir)/il2cpp.exe" \
		--directory="$(<D)" \
		--convert-to-cpp \
		--emit-null-checks \
		--enable-array-bounds-check \
		--dotnetprofile="unityaot" \
		--copy-level=None \
		--generatedcppdir="$(@D)"

$(LINKED_DLL_TARGET): $(DLL_TARGET)
	@ echo "[$(UNITY_VERSION)] Linking $(<F)"
	@ $(MAYBE_STRACE) "$(mono_dir)/bin-linux64/mono" \
		"$(il2cpp_dir)/UnityLinker.exe" \
		--include-assembly="$<,$(mono_dir)/lib/mono/unityaot/mscorlib.dll" \
		--i18n=none \
		--core-action=link \
		--dotnetruntime=il2cpp \
		--dotnetprofile=unityaot \
		--use-editor-options \
		--out="$(@D)"

$(DLL_TARGET): $(CS_SRC) $(EDITOR_DIR) $(BUILD_DIR)
	@ echo "[$(UNITY_VERSION)] Compiling $(<F)"
	@ mkdir -p $(@D)
	@ $(MAYBE_STRACE) "$(mono_dir)/bin-linux64/mono" \
		"$(mono_dir)/lib/mono/4.5/csc.exe" \
		-target:library \
		-nologo \
		-unsafe \
		-out:"$@" \
		"$<"

$(EDITOR_DIR):
	@ echo "[$(UNITY_VERSION)] Downloading editor..."
	@ curl -L -s -A "" --fail https://download.unity3d.com/download_unity/ffacea4b84e7/LinuxEditorInstaller/Unity.tar.xz -O

	@ echo "[$(UNITY_VERSION)] Extracting editor..."
	@ tar -xf Unity.tar.xz
	@ touch -m Editor

	@ echo "[$(UNITY_VERSION)] Cleanup..."
	@ rm Unity.tar.xz
