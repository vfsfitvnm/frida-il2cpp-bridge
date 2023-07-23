include ../common.mk

UNITY_LINKER := $(MONO) $(IL2CPP_DIR)/build/UnityLinker.exe
IL2CPP := $(MONO) $(IL2CPP_DIR)/build/il2cpp.exe

MSCORLIB := $(MONO_DIR)/lib/mono/2.0/mscorlib.dll

export TERM = xterm

$(ASSEMBLY_TARGET): $(CPP_TARGET)
	@ echo "[$(UNITY_VERSION)] Compiling $(<F)"
	@ $(IL2CPP) \
		--generatedcppdir="$(<D)" \
		--compile-cpp \
		--libil2cpp-static \
		--configuration=Release \
		--platform=Linux \
		--architecture=x64 \
		--dotnetprofile=net20 \
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
		--dotnetprofile=net20 \
		--copy-level=None \
		--generatedcppdir="$(@D)"

$(LINKED_DLL_TARGET): $(DLL_TARGET)
	@ echo "[$(UNITY_VERSION)] Linking $(<F)"
	@ $(UNITY_LINKER) \
		--dotnetruntime=il2cpp \
		--dotnetprofile=net20 \
		--include-assembly="$<,$(MSCORLIB)" \
		--descriptor-directory="$(LINKER_DESCRIPTORS_DIR)" \
		--disable-keep-facades \
		--i18n=none \
		--core-action=link \
		--out="$(@D)"

$(EDITOR_DIR):
	@ echo "[$(UNITY_VERSION)] Downloading editor..."
	@ curl -L -s -A "" --fail https://netstorage.unity3d.com/unity/6e9a27477296/LinuxEditorInstaller/Unity.tar.xz -O

	@ echo "[$(UNITY_VERSION)] Extracting editor..."
	@ tar -xf Unity.tar.xz
	@ touch -m Editor

	@ echo "[$(UNITY_VERSION)] Cleanup..."
	@ rm Unity.tar.xz
