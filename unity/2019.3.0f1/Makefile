include ../common.mk

UNITY_CHANGESET := ffacea4b84e7
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
	--i18n=none \
	--disable-keep-facades \
	--silent \
	--core-action=link \
	--strip-security \
	--rule-set=aggressive \
	--dotnetruntime=il2cpp \
	--dotnetprofile=unityaot \
	--descriptor-directory="$(LINKER_DESCRIPTORS_DIR)" \
	--include-assembly="$<,$(MSCORLIB)" \
	--out="$(@D)"
