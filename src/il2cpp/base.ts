import { cache } from "decorator-cache-getter";

import { UnityVersion } from "./version";

import { platformNotSupported, raise, warn } from "../utils/console";
import { forModule } from "../utils/native-wait";

/** */
class Il2CppBase {
    protected constructor() {}

    /** */
    static get allocationGranularity(): number {
        return Il2Cpp.Api._allocationGranularity();
    }

    /** @internal */
    private static get il2CppModuleName(): string {
        return Process.platform == "linux" ? "libil2cpp.so" : Process.platform == "windows" ? "GameAssembly.dll" : platformNotSupported();
    }

    /** The Il2Cpp module. */
    @cache
    static get module(): Module {
        return Process.getModuleByName(this.il2CppModuleName);
    }

    /** @internal */
    private static get unityModuleName(): string {
        return Process.platform == "linux" ? "libunity.so" : Process.platform == "windows" ? "UnityPlayer.dll" : platformNotSupported();
    }

    /** The Unity version of the current application. */
    @cache
    static get unityVersion(): UnityVersion {
        const unityModule = Process.getModuleByName(this.unityModuleName);
        const ranges = [...unityModule.enumerateRanges("r--"), Process.getRangeByAddress(unityModule.base)];

        for (const range of ranges) {
            const scan = Memory.scanSync(range.base, range.size, "45787065637465642076657273696f6e3a")[0];

            if (scan != undefined) {
                const unityVersion = new UnityVersion(scan.address.readUtf8String()!);

                if (unityVersion.isBelow("5.3.0") || unityVersion.isEqualOrAbove("2021.2.0")) {
                    raise(`Unity version "${unityVersion}" is not valid or supported.`);
                }

                return unityVersion;
            }
        }

        raise("Couldn't obtain the Unity version.");
    }

    static alloc(size: number | UInt64 = Process.pointerSize): NativePointer {
        return Il2Cpp.Api._alloc(size);
    }

    static dump(): Pick<Il2Cpp.Dumper, "directoryPath" | "fileName" | "classes" | "methods"> {
        return new Il2Cpp.Dumper();
    }

    static free(pointer: NativePointerValue): void {
        return Il2Cpp.Api._free(pointer);
    }

    static trace(): Pick<Il2Cpp.Tracer, "domain" | "assemblies" | "classes" | "methods"> {
        return new Il2Cpp.Tracer();
    }

    /** @internal Waits for Il2Cpp native libraries to be loaded and initialized. */
    private static async initialize(): Promise<void> {
        if (Script.runtime != "V8") {
            warn("Frida's JavaScript runtime is not V8 (--runtime=v8). Proceed with caution.");
        }

        await forModule(this.unityModuleName);
        await forModule(this.il2CppModuleName);

        if (Il2Cpp.Api._getCorlib().isNull()) {
            await new Promise<void>(resolve => {
                const interceptor = Interceptor.attach(Il2Cpp.Api._init, {
                    onLeave() {
                        setImmediate(() => {
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
            let thread = Il2Cpp.Thread.current;
            const isForeignThread = thread == null;

            if (isForeignThread) {
                thread = Il2Cpp.Domain.attach();
            }

            block();

            if (isForeignThread) {
                thread?.detach();
            }
        }

        this.initialize()
            .then(executor)
            .catch(error => Script.nextTick(() => (globalThis as any).console.log(error.stack)));
    }
}

Reflect.set(globalThis, "Il2Cpp", Il2CppBase);

declare global {
    class Il2Cpp extends Il2CppBase {}
}
