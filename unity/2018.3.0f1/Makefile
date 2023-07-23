include ../common.mk

UNITY_LINKER := $(MONO) $(IL2CPP_DIR)/build/UnityLinker.exe
IL2CPP := $(MONO) $(IL2CPP_DIR)/build/il2cpp.exe

MSCORLIB := $(MONO_DIR)/lib/mono/2.0/mscorlib.dll

export TERM = xterm

ASSEMBLY_TARGET_CMD = $(IL2CPP) \
	--compile-cpp \
	--libil2cpp-static \
	--configuration=Release \
	--platform=Linux \
	--architecture=x64 \
	--dotnetprofile=net20 \
	--cachedirectory="$(@D)/../buildstate"
	--generatedcppdir="$(<D)" \
	--outputpath="$@" \

CPP_TARGET_CMD = $(IL2CPP) \
	--convert-to-cpp \
	--emit-null-checks \
	--enable-array-bounds-check \
	--copy-level=None \
	--dotnetprofile=net20 \
	--directory="$(<D)" \
	--generatedcppdir="$(@D)"

LINKED_DLL_TARGET_CMD = $(UNITY_LINKER) \
	--disable-keep-facades \
	--i18n=none \
	--core-action=link \
	--dotnetruntime=il2cpp \
	--dotnetprofile=net20 \
	--descriptor-directory="$(LINKER_DESCRIPTORS_DIR)" \
	--include-assembly="$<,$(MSCORLIB)" \
	--out="$(@D)"

$(EDITOR_DIR):
	@ echo "[$(UNITY_VERSION)] Downloading editor..."
	@ curl -L -s -A "" --fail https://netstorage.unity3d.com/unity/6e9a27477296/LinuxEditorInstaller/Unity.tar.xz -O

	@ echo "[$(UNITY_VERSION)] Extracting editor..."
	@ tar -xf Unity.tar.xz
	@ touch -m Editor

	@ echo "[$(UNITY_VERSION)] Cleanup..."
	@ rm Unity.tar.xz
