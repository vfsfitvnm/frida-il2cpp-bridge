include ../common.mk

UNITY_LINKER := $(MONO) $(IL2CPP_DIR)/build/deploy/net471/UnityLinker.exe
IL2CPP := $(MONO) $(IL2CPP_DIR)/build/deploy/net471/il2cpp.exe

MSCORLIB := $(MONOBL_DIR)/lib/mono/unityaot/mscorlib.dll

export TERM = xterm

ASSEMBLY_TARGET_CMD = $(IL2CPP) \
	--compile-cpp \
	--libil2cpp-static \
	--configuration=Release \
	--platform=Linux \
	--architecture=x64 \
	--dotnetprofile=unityaot \
	--cachedirectory="$(@D)/../buildstate" \
	--generatedcppdir="$(<D)" \
	--outputpath="$@"

CPP_TARGET_CMD = $(IL2CPP) \
	--convert-to-cpp \
	--emit-null-checks \
	--enable-array-bounds-check \
	--copy-level=None \
	--dotnetprofile=unityaot \
	--directory="$(<D)" \
	--generatedcppdir="$(@D)"

LINKED_DLL_TARGET_CMD = $(UNITY_LINKER) \
	--silent \
	--i18n=none \
	--core-action=link \
	--strip-security \
	--rule-set=aggressive \
	--dotnetruntime=il2cpp \
	--dotnetprofile=unityaot \
	--descriptor-directory="$(LINKER_DESCRIPTORS_DIR)" \
	--include-assembly="$<,$(MSCORLIB)" \
	--out="$(@D)"

$(EDITOR_DIR):
	@ echo "[$(UNITY_VERSION)] Downloading editor..."
	@ curl -L -s -A "" --fail https://download.unity3d.com/download_unity/ffacea4b84e7/LinuxEditorInstaller/Unity.tar.xz -O

	@ echo "[$(UNITY_VERSION)] Extracting editor..."
	@ tar -xf Unity.tar.xz
	@ touch -m Editor

	@ echo "[$(UNITY_VERSION)] Cleanup..."
	@ rm Unity.tar.xz
