import { platformNotSupported, raise } from "../utils/console";
import { forModule } from "../utils/native-wait";

import { UnityVersion } from "./version";

/**
 * The Il2Cpp library (`libil2cpp.so`, `GameAssembly.dll` ...).
 */
export let library: Module;

/**
 * The Unity version of the current application.
 */
export let unityVersion: UnityVersion;

/**
 * The whole thing must be initialized first.
 * This is potentially asynchronous because
 * the `IL2CPP` library could be loaded at any
 * time, so we just make sure it's loaded.
 * The current Unity version will also be
 * detected.
 * ```typescript
 * import "frida-il2cpp-bridge";
 * async function main() {
 *   await Il2Cpp.initialize();
 *   console.log(Il2Cpp.unityVersion);
 * }
 * main().catch(error => console.log(error.stack));
 ```
 */
export async function initialize(): Promise<void> {
    const il2CppLibraryName =
        Process.platform == "linux" ? "libil2cpp.so" : Process.platform == "windows" ? "GameAssembly.dll" : platformNotSupported();

    library = await forModule(il2CppLibraryName);
    unityVersion = await getUnityVersion();
}

async function getUnityVersion(): Promise<UnityVersion> {
    const unityLibraryName =
        Process.platform == "linux" ? "libunity.so" : Process.platform == "windows" ? "UnityPlayer.dll" : platformNotSupported();

    let unityVersion: UnityVersion | undefined;
    const searchStringHex = "45787065637465642076657273696f6e3a"; // "Expected version: "

    try {
        const unityLibrary = await forModule(unityLibraryName);
        for (const range of unityLibrary.enumerateRanges("r--").concat(Process.getRangeByAddress(unityLibrary.base))) {
            const result = Memory.scanSync(range.base, range.size, searchStringHex)[0];
            if (result !== undefined) {
                unityVersion = new UnityVersion(result.address.readUtf8String()!);
                break;
            }
        }
    } catch (e) {
        raise("Couldn't obtain the Unity version: " + e);
    }

    if (unityVersion == undefined) {
        raise("Couldn't obtain the Unity version.");
    } else if (unityVersion.isBelow("5.3.0") || unityVersion.isEqualOrAbove("2021.1.0")) {
        raise(`Unity version "${unityVersion}" is not valid or supported.`);
    }

    return unityVersion;
}
