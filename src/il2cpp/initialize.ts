import { Api } from "./api";
import { injectToIl2Cpp } from "./decorators";
import { UnityVersion } from "./version";

import { platformNotSupported, raise, warn } from "../utils/console";
import { forModule } from "../utils/native-wait";

async function setUnityVersion(): Promise<void> {
    const unityModuleName =
        Process.platform == "linux" ? "libunity.so" : Process.platform == "windows" ? "UnityPlayer.dll" : platformNotSupported();

    const unityModule = await forModule(unityModuleName);
    const range = Process.getRangeByAddress(unityModule.base);

    Memory.scan(range.base, range.size, "45787065637465642076657273696f6e3a", {
        onMatch(address: NativePointer): EnumerateAction {
            injectToIl2Cpp("unityVersion")(new UnityVersion(address.readUtf8String()!));
            return "stop";
        },
        onComplete(): void {
            if (Il2Cpp.unityVersion == undefined) {
                raise("Couldn't obtain the Unity version.");
            } else if (Il2Cpp.unityVersion.isBelow("5.3.0") || Il2Cpp.unityVersion.isEqualOrAbove("2021.1.0")) {
                raise(`Unity version "${Il2Cpp.unityVersion}" is not valid or supported.`);
            }
        }
    });
}

async function initialize(): Promise<void> {
    if (Script.runtime != "V8") {
        warn("Frida's JavaScript runtime is not V8 (--runtime=v8). Proceed with caution.");
    }

    const il2CppModuleName =
        Process.platform == "linux" ? "libil2cpp.so" : Process.platform == "windows" ? "GameAssembly.dll" : platformNotSupported();

    await setUnityVersion();
    injectToIl2Cpp("module")(await forModule(il2CppModuleName));

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

    Api._threadAttach(Il2Cpp.Domain.reference); // Yes, it will leak
}

injectToIl2Cpp("initialize")(initialize);
