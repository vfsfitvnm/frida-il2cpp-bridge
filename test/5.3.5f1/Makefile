mono := "./Editor/Data/Mono/bin/mono"
mono_lib := ./Editor/Data/Mono/lib/mono/unity
mono_be := "./Editor/Data/MonoBleedingEdge/bin/mono"
il2cpp := $(mono_be) "./Editor/Data/il2cpp/build/il2cpp.exe"

export TERM = xterm

assembly: prepare .build/out/GameAssembly.so

.build/out/%.so: .build/cpp/Bulk_%_0.cpp
	@ echo "Compiling $(<F)"
	@ $(il2cpp) \
		--generatedcppdir="$(<D)" \
		--compile-cpp \
		--libil2cpp-static \
		--configuration=Release \
		--platform=Linux \
		--architecture=x64 \
		--outputpath="$(CURDIR)/$@" \
		--cachedirectory="$(@D)/.."
	@ strip "$@"

.build/cpp/Bulk_%_0.cpp: .build/linked/%.dll
	@ echo "Generating $(@F)"
	@ $(il2cpp) \
		--assembly="$^" \
		--convert-to-cpp \
		--emit-null-checks \
		--enable-array-bounds-check \
		--copy-level=None \
		--generatedcppdir="$(@D)"

.build/linked/%.dll: export MONO_PATH=$(mono_lib)
.build/linked/%.dll: .build/dll/%.dll
	@ echo "Linking $(<F)"
	@ $(mono) \
		"./Editor/Data/Tools/UnusedBytecodeStripper.exe" \
		-l none \
		-c link \
		-b false \
		-x "./Editor/Data/Tools/link.xml" \
		-out "$(@D)" \
		-a "$(mono_lib)/mscorlib.dll" \
		-a "$<"

.build/dll/%.dll: export MONO_PATH=$(mono_lib)
.build/dll/%.dll:
	@ echo "Compiling $*.cs"
	@ mkdir -p $(@D)
	@ $(mono) \
		"$(mono_lib)/smcs.exe" \
		-target:library \
		-out:"$@" \
		"../$*.cs"

prepare:
	@ mkdir -p .build

clean:
	@ rm -r .build

editor.deb:
	@ echo "Downloading Unity 5.3.5f1..."
	@ curl -L -s -A "" --fail "http://download.unity3d.com/download_unity/linux/unity-editor-5.3.5f1+20160525_amd64.deb" -o "$@"

data.tar.gz: editor.deb
	@ ar x editor.deb
	@ ar t editor.deb | grep -v -e data.tar.gz | xargs rm
	@ rm $<

Editor: data.tar.gz
	@ tar -xf $< --strip-components=3 --files-from=.tarinclude
	@ rm $<
	@ touch -m Editor

.PHONY: assembly clean prepare

.SECONDARY:
