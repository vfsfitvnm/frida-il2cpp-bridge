include ../build.mk

UNITY_LINKER := $(MONO) $(EDITOR_DIR)/Data/Tools/UnusedBytecodeStripper.exe
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
	--cachedirectory="$(@D)/.." \
	--generatedcppdir="$(<D)" \
	--outputpath="$@"

CPP_TARGET_CMD = $(IL2CPP) \
	--convert-to-cpp \
	--emit-null-checks \
	--enable-array-bounds-check \
	--copy-level=None \
	--dotnetprofile=net20 \
	--assembly="$^" \
	--generatedcppdir="$(@D)"

LINKED_DLL_TARGET_CMD = $(UNITY_LINKER) \
	-l none \
	-b false \
	-c link \
	-x "$(LINKER_DESCRIPTORS_DIR)/mscorlib.xml" \
	-a "$(MSCORLIB)" \
	-a "$<" \
	-out "$(@D)"
