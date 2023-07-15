mono_dir := ./Editor/Data/MonoBleedingEdge
il2cpp_dir := ./Editor/Data/il2cpp/build/deploy

assembly: prepare .build/out/GameAssembly.so

.build/out/%.so: .build/cpp/%.cpp
	@ echo "Compiling $(<F)"
	@ "$(il2cpp_dir)/il2cpp" \
		--generatedcppdir="$(<D)" \
		--baselib-directory="$(CURDIR)/Editor/Data/PlaybackEngines/LinuxStandaloneSupport/Variations/linux64_player_nondevelopment_il2cpp/" \
		--compile-cpp \
		--libil2cpp-static \
		--configuration=Release \
		--platform=Linux \
		--architecture=x64 \
		--dotnetprofile=unityaot-linux \
		--outputpath="$(CURDIR)/$@" \
		--cachedirectory="$(@D)/.."
	@ strip "$@"

.build/cpp/%.cpp: .build/linked/%.dll
	@ echo "Generating $(@F)"
	@ "$(il2cpp_dir)/il2cpp" \
		--directory="$(<D)" \
		--convert-to-cpp \
		--emit-null-checks \
		--enable-array-bounds-check \
		--dotnetprofile="unityaot-linux" \
		--copy-level=None \
		--generatedcppdir="$(@D)"

.build/linked/%.dll: .build/dll/%.dll
	@ echo "Linking $(<F)"
	@ "$(il2cpp_dir)/UnityLinker" \
		--include-assembly="$<,$(mono_dir)/lib/mono/unityaot-linux/mscorlib.dll" \
		--i18n=none \
		--core-action=link \
		--dotnetruntime=il2cpp \
		--dotnetprofile=unityaot-linux \
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
