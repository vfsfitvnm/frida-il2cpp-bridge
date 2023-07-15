mono_dir := ./Editor/Data/MonoBleedingEdge
il2cpp_dir := ./Editor/Data/il2cpp/build/deploy/net471

export TERM = xterm

assembly: prepare .build/out/GameAssembly.so

.build/out/%.so: .build/cpp/%.cpp
	@ echo "Compiling $(<F)"
	"$(mono_dir)/bin-linux64/mono" \
		"$(il2cpp_dir)/il2cpp.exe" \
		--generatedcppdir="$(<D)" \
		--compile-cpp \
		--libil2cpp-static \
		--configuration=Release \
		--platform=Linux \
		--architecture=x64 \
		--dotnetprofile=unityaot \
		--outputpath="$(CURDIR)/$@" \
		--cachedirectory="$(@D)/../buildstate"
	@ strip "$@"

.build/cpp/%.cpp: .build/linked/%.dll
	@ echo "Generating $(@F)"
	@ "$(mono_dir)/bin-linux64/mono" \
		"$(il2cpp_dir)/il2cpp.exe" \
		--directory="$(<D)" \
		--convert-to-cpp \
		--emit-null-checks \
		--enable-array-bounds-check \
		--dotnetprofile="unityaot" \
		--copy-level=None \
		--generatedcppdir="$(@D)"

.build/linked/%.dll: .build/dll/%.dll
	@ echo "Linking $(<F)"
	@ "$(mono_dir)/bin-linux64/mono" \
		"$(il2cpp_dir)/UnityLinker.exe" \
		--include-assembly="$<,$(mono_dir)/lib/mono/unityaot/mscorlib.dll" \
		--i18n=none \
		--core-action=link \
		--dotnetruntime=il2cpp \
		--dotnetprofile=unityaot \
		--use-editor-options \
		--out="$(@D)"

.build/dll/%.dll:
	@ echo "Compiling $*.cs"
	@ mkdir -p $(@D)
	@ "$(mono_dir)/bin-linux64/mono" \
		"$(mono_dir)/lib/mono/4.5/csc.exe" \
		-target:library \
		-nologo \
		-unsafe \
		-out:"$@" \
		"../$*.cs"

prepare:
	@ mkdir -p .build

clean:
	@ rm -r .build

.PHONY: assembly clean prepare

.SECONDARY:
