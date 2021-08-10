import { cache } from "decorator-cache-getter";

import { UnityVersion } from "./version";

import { platformNotSupported, raise, warn } from "../utils/console";
import { forModule } from "../utils/native-wait";

/** */
class Il2CppBase {
    protected constructor() {}

    /** @internal */
    static get il2CppModuleName(): string {
        return Process.platform == "linux" ? "libil2cpp.so" : Process.platform == "windows" ? "GameAssembly.dll" : platformNotSupported();
    }

    /** The Il2Cpp module. */
    @cache
    static get module(): Module {
        return Process.getModuleByName(this.il2CppModuleName);
    }

    /** @internal */
    static get unityModuleName(): string {
        return Process.platform == "linux" ? "libunity.so" : Process.platform == "windows" ? "UnityPlayer.dll" : platformNotSupported();
    }

    /** The Unity version of the current application. */
    @cache
    static get unityVersion(): UnityVersion {
        const range = Process.getRangeByAddress(Process.getModuleByName(this.unityModuleName).base);

        const address = Memory.scanSync(range.base, range.size, "45787065637465642076657273696f6e3a")[0].address;
        const unityVersion = new UnityVersion(address.readUtf8String()!);

        if (unityVersion == undefined) {
            raise("Couldn't obtain the Unity version.");
        } else if (unityVersion.isBelow("5.3.0") || unityVersion.isEqualOrAbove("2021.1.0")) {
            raise(`Unity version "${unityVersion}" is not valid or supported.`);
        }

        return unityVersion;
    }

    /** @internal Waits for Il2Cpp native libraries to be loaded and initialized. */
    static async initialize(): Promise<void> {
        if (Script.runtime != "V8") {
            warn("Frida's JavaScript runtime is not V8 (--runtime=v8). Proceed with caution.");
        }

        await forModule(this.unityModuleName);
        await forModule(this.il2CppModuleName);

        if (Il2Cpp.Api._getCorlib().isNull()) {
            await new Promise<void>(resolve => {
                const interceptor = Interceptor.attach(Il2Cpp.Api._init, {
                    onLeave() {
                        setTimeout(() => {
                            interceptor.detach();
                            resolve();
                        });
                    }
                });
            });
        }
    }

    /** Attaches the caller thread to Il2Cpp domain and executes the given block.  */
    static perform(block: () => void): void {
        function executor() {
            const isForeignThread = Il2Cpp.Api._threadCurrent().isNull();

            if (isForeignThread) {
                Il2Cpp.Api._threadAttach(Il2Cpp.Domain.reference);
            }

            block();

            if (isForeignThread) {
                Il2Cpp.Api._threadDetach(Il2Cpp.Api._threadCurrent());
            }
        }

        this.initialize()
            .then(executor)
            .catch(error => console.log(error.stack));
    }
}

Reflect.set(globalThis, "Il2Cpp", Il2CppBase);

declare global {
    class Il2Cpp extends Il2CppBase {}
}
