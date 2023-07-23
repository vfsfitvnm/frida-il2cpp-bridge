include ../common.mk

UNITY_LINKER := $(MAYBE_STRACE) $(IL2CPP_DIR)/build/deploy/UnityLinker
IL2CPP := $(MAYBE_STRACE) $(IL2CPP_DIR)/build/deploy/il2cpp

MSCORLIB := $(MONOBL_DIR)/lib/mono/unityaot-linux/mscorlib.dll

$(ASSEMBLY_TARGET): $(CPP_TARGET)
	@ echo "[$(UNITY_VERSION)] Compiling $(<F)"
	@ $(IL2CPP) \
		--baselib-directory="$(EDITOR_DIR)/Data/PlaybackEngines/LinuxStandaloneSupport/Variations/linux64_player_nondevelopment_il2cpp/" \
		--generatedcppdir="$(<D)" \
		--compile-cpp \
		--libil2cpp-static \
		--configuration=Release \
		--platform=Linux \
		--architecture=x64 \
		--dotnetprofile=unityaot-linux \
		--outputpath="$@" \
		--cachedirectory="$(@D)/../buildstate"
	@ strip "$@"

$(CPP_TARGET): $(LINKED_DLL_TARGET)
	@ echo "[$(UNITY_VERSION)] Generating $(@F)"
	@ $(IL2CPP) \
		--directory="$(<D)" \
		--convert-to-cpp \
		--emit-null-checks \
		--enable-array-bounds-check \
		--dotnetprofile=unityaot-linux \
		--copy-level=None \
		--generatedcppdir="$(@D)"

$(LINKED_DLL_TARGET): $(DLL_TARGET)
	@ echo "[$(UNITY_VERSION)] Linking $(<F)"
	@ $(UNITY_LINKER) \
		--silent \
		--strip-security \
		--rule-set=aggressive \
		--dotnetruntime=il2cpp \
		--dotnetprofile=unityaot-linux \
		--include-assembly="$<,$(MSCORLIB)" \
		--descriptor-directory="$(LINKER_DESCRIPTORS_DIR)" \
		--i18n=none \
		--core-action=link \
		--out="$(@D)"

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