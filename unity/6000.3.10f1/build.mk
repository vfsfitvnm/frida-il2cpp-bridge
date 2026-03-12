include ../build.mk

UNITY_LINKER := $(MAYBE_STRACE) $(IL2CPP_DIR)/build/deploy/UnityLinker
IL2CPP := $(MAYBE_STRACE) $(IL2CPP_DIR)/build/deploy/il2cpp

MSCORLIB := $(MONOBL_DIR)/lib/mono/unityaot-linux/mscorlib.dll

# It looks like Unity (rightfully) expects its toolchain (com.unity.toolchain.linux-x86_64) to
# be downloaded and used (so that every machine has the same binaries - e.g. Clang9 - and libraries).
# Now, il2cpp executable expects a --sysroot-path and a --tool-chain-path that point to their packages.
# After wasting few hours on this, the following flags will bring back the classic behavior:
# 	--sysroot-path="/dummy/path" (can be any path, at least two levels deep)
#   --tool-chain-path="/usr" (can be anything?)
# 	--compiler-flags="--sysroot=\"\" --gcc-toolchain=\"\"" (override values passed by il2cpp executable)
# 	--linker-flags="-fuse-ld=\"\"" (override values passed by il2cpp executable)
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
	--sysroot-path="/dummy/path" \
	--tool-chain-path="/usr" \
	--compiler-flags="--sysroot=\"\" --gcc-toolchain=\"\"" \
	--linker-flags="-fuse-ld=\"\"" \
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
