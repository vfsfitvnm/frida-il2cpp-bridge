include ../common.mk

mono_dir := $(EDITOR_DIR)/Data/MonoBleedingEdge
il2cpp_dir := $(EDITOR_DIR)/Data/il2cpp/build/deploy

$(ASSEMBLY_TARGET): $(CPP_TARGET)
	@ echo "[$(UNITY_VERSION)] Compiling $(<F)"
	@ $(MAYBE_STRACE) "$(il2cpp_dir)/il2cpp" \
		--generatedcppdir="$(<D)" \
		--baselib-directory="$(EDITOR_DIR)/Data/PlaybackEngines/LinuxStandaloneSupport/Variations/linux64_player_nondevelopment_il2cpp/" \
		--compile-cpp \
		--libil2cpp-static \
		--configuration=Release \
		--platform=Linux \
		--architecture=x64 \
		--dotnetprofile=unityaot-linux \
		--outputpath="$@" \
		--cachedirectory="$(@D)/.."
	@ strip "$@"

$(CPP_TARGET): $(LINKED_DLL_TARGET)
	@ echo "[$(UNITY_VERSION)] Generating $(@F)"
	@ $(MAYBE_STRACE) "$(il2cpp_dir)/il2cpp" \
		--directory="$(<D)" \
		--convert-to-cpp \
		--emit-null-checks \
		--enable-array-bounds-check \
		--dotnetprofile="unityaot-linux" \
		--copy-level=None \
		--generatedcppdir="$(@D)"

$(LINKED_DLL_TARGET): $(DLL_TARGET)
	@ echo "[$(UNITY_VERSION)] Linking $(<F)"
	@ $(MAYBE_STRACE) "$(il2cpp_dir)/UnityLinker" \
		--include-assembly="$<,$(mono_dir)/lib/mono/unityaot-linux/mscorlib.dll" \
		--i18n=none \
		--core-action=link \
		--dotnetruntime=il2cpp \
		--dotnetprofile=unityaot-linux \
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
	@ curl -L -s -A "" --fail https://netstorage.unity3d.com/unity/4bf1ec4b23c9/LinuxEditorInstaller/Unity.tar.xz -O

	@ echo "[$(UNITY_VERSION)] Extracting editor..."
	@ tar -xf Unity.tar.xz
	@ touch -m Editor

	@ echo "[$(UNITY_VERSION)] Cleanup..."
	@ rm Unity.tar.xz

	@ echo "[$(UNITY_VERSION)] Downloading editor support..."
	@ curl --progress-bar -L -s -A "" --fail https://download.unity3d.com/download_unity/4bf1ec4b23c9/LinuxEditorTargetInstaller/UnitySetup-Linux-IL2CPP-Support-for-Editor-2021.2.0f1.tar.xz -o Support.tar.xz

	@ echo "[$(UNITY_VERSION)] Extracting editor support..."
	@ tar -xf Support.tar.xz
	@ touch -m Editor

	@ echo "[$(UNITY_VERSION)] Cleanup..."
	@ rm Support.tar.xz