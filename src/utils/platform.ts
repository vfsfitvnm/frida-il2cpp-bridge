import { raise } from "./console";

/** @internal */
function platformNotSupported(): never {
    raise(`Platform "${Process.platform}" is not supported yet.`);
}

/** @internal */
export const il2CppLibraryName =
    Process.platform == "linux"
        ? "libil2cpp.so"
        : Process.platform == "windows"
        ? "GameAssembly.dll"
        : Process.platform == "darwin"
        ? platformNotSupported()
        : platformNotSupported();

/** @internal */
export const unityLibraryName =
    Process.platform == "linux"
        ? "libunity.so"
        : Process.platform == "windows"
        ? "UnityPlayer.dll"
        : Process.platform == "darwin"
        ? platformNotSupported()
        : platformNotSupported();

/** @internal */
const loader =
    Process.platform == "linux"
        ? Module.getExportByName("libc.so", "dlopen")
        : Process.platform == "windows"
        ? Module.getExportByName("kernel32.dll", "LoadLibraryW")
        : Process.platform == "darwin"
        ? platformNotSupported()
        : platformNotSupported();

/** @internal */
export function forLibrary(libraryName: string) {
    return new Promise<Module>(resolve => {
        const library = Process.findModuleByName(libraryName);
        if (library != null) {
            resolve(library);
        } else {
            const interceptor = Interceptor.attach(loader, {
                onEnter(args) {
                    const moduleName = Process.platform == "windows" ? args[0].readUtf16String() : args[0].readCString();
                    this.isMatch = moduleName?.endsWith(libraryName);
                },
                onLeave() {
                    if (this.isMatch) {
                        setTimeout(() => interceptor.detach());
                        resolve(Process.getModuleByName(libraryName));
                    }
                }
            });
        }
    });
}
