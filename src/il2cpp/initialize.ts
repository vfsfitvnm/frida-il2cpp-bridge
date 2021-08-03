import { Api } from "./api";
import { injectToIl2Cpp } from "./decorators";
import { UnityVersion } from "./version";

import { platformNotSupported, raise, warn } from "../utils/console";
import { forModule } from "../utils/native-wait";

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

async function initialize(): Promise<void> {
    if (Script.runtime != "V8") {
        warn("Frida's JavaScript runtime is not V8 (--runtime=v8). Proceed with caution.");
    }

    const il2CppLibraryName =
        Process.platform == "linux" ? "libil2cpp.so" : Process.platform == "windows" ? "GameAssembly.dll" : platformNotSupported();

    injectToIl2Cpp("unityVersion")(await getUnityVersion());
    injectToIl2Cpp("module")(await forModule(il2CppLibraryName));

    if (Api._getCorlib().isNull()) {
        await new Promise<void>(resolve => {
            const interceptor = Interceptor.attach(Api._init, {
                onLeave() {
                    interceptor.detach();
                    resolve();
                }
            });
        });
    }
    Api._threadAttach(Il2Cpp.Domain.reference);
}

injectToIl2Cpp("initialize")(initialize);
