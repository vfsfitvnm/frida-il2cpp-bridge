/** @internal */
export const il2CppLibraryName =
    Process.platform == "linux"
        ? "libil2cpp.so"
        : Process.platform == "windows"
        ? "GameAssembly.dll"
        : Process.platform == "darwin"
        ? undefined
        : undefined;

/** @internal */
export const unityLibraryName =
    Process.platform == "linux"
        ? "libunity.so"
        : Process.platform == "windows"
        ? "UnityPlayer.dll"
        : Process.platform == "darwin"
        ? undefined
        : undefined;

/** @internal */
const loader =
    Process.platform == "linux"
        ? Module.getExportByName("libc.so", "dlopen")
        : Process.platform == "windows"
        ? undefined
        : Process.platform == "darwin"
        ? undefined
        : undefined;

/** @internal */
export function forLibrary(libraryName: string): Promise<void> {
    return new Promise((resolve) => {
        const library = Process.findModuleByName(libraryName);
        if (library != null) {
            resolve();
        } else {
            const interceptor = Interceptor.attach(loader!, {
                onEnter(args) {
                    this.isMatch = args[0].readCString()?.endsWith(libraryName);
                },
                onLeave() {
                    if (this.isMatch) {
                        setTimeout(() => interceptor.detach());
                        resolve();
                    }
                },
            });
        }
    });
}

// export function waitForUnityLibrary() {
//     return waitForLibrary(unityLibraryName!);
// }
//
// export function waitForIl2CppLibrary() {
//     return waitForLibrary(il2CppLibraryName!);
// }
