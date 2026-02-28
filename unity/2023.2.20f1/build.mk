include ../build.mk

UNITY_LINKER := $(MAYBE_STRACE) $(IL2CPP_DIR)/build/deploy/UnityLinker
IL2CPP := $(MAYBE_STRACE) $(IL2CPP_DIR)/build/deploy/il2cpp

MSCORLIB := $(MONOBL_DIR)/lib/mono/unityaot-linux/mscorlib.dll

ASSEMBLY_TARGET_CMD = $(IL2CPP) \
	--compile-cpp \
	--libil2cpp-static \
	--configuration=Release \
	--platform=Linux \
	--architecture=x64 \
	--dotnetprofile=unityaot-linux \
	--cachedirectory="$(@D)/.." \
	--generatedcppdir="$(<D)" \
	--baselib-directory="$(EDITOR_DIR)/Data/PlaybackEngines/LinuxStandaloneSupport/Variations/linux64_player_nondevelopment_il2cpp/" \
	--outputpath="$@"

CPP_TARGET_CMD = $(IL2CPP) \
	--convert-to-cpp \
	--emit-null-checks \
	--enable-array-bounds-check \
	--dotnetprofile=unityaot-linux \
	--copy-level=None \
	--directory="$(<D)" \
	--generatedcppdir="$(@D)"

LINKED_DLL_TARGET_CMD = $(UNITY_LINKER) \
	--silent \
	--i18n=none \
	--core-action=link \
	--strip-security \
	--rule-set=aggressive \
	--dotnetruntime=il2cpp \
	--dotnetprofile=unityaot-linux \
	--descriptor-directory="$(LINKER_DESCRIPTORS_DIR)" \
	--include-assembly="$<,$(MSCORLIB)" \
	--out="$(@D)"
