import { cache } from "decorator-cache-getter";
import { platformNotSupported, warn } from "../utils/console";
import { forModule } from "../utils/native-wait";

/** */
class Il2CppBase {
    protected constructor() {}

    /** @internal Gets the Il2Cpp module name. */
    private static get moduleName(): string {
        switch (Process.platform) {
            case "linux":
                try {
                    const _ = Java.androidVersion;
                    return "libil2cpp.so";
                } catch (e) {
                    return "GameAssembly.so";
                }
            case "windows":
                return "GameAssembly.dll";
            case "darwin":
                try {
                    return "UnityFramework";
                } catch (e) {
                    return "GameAssembly.dylib";
                }
        }

        platformNotSupported();
    }

    /** Gets the Il2Cpp module as a Frida module. */
    @cache
    static get module(): Module {
        return Process.getModuleByName(this.moduleName);
    }

    /** Allocates the given amount of bytes. */
    static alloc(size: number | UInt64 = Process.pointerSize): NativePointer {
        return Il2Cpp.Api._alloc(size);
    }

    /** Creates a new `Il2Cpp.Dumper` instance. */
    static dump(): Pick<Il2Cpp.Dumper, "directoryPath" | "fileName" | "classes" | "methods"> {
        return new Il2Cpp.Dumper();
    }

    /** Frees memory. */
    static free(pointer: NativePointerValue): void {
        return Il2Cpp.Api._free(pointer);
    }

    /** Creates a new `Il2Cpp.Tracer` instance. */
    static trace(): Pick<Il2Cpp.Tracer, "domain" | "assemblies" | "classes" | "methods"> {
        return new Il2Cpp.Tracer();
    }

    /** @internal Waits for Unity and Il2Cpp native libraries to be loaded and initialized. */
    private static async initialize(): Promise<void> {
        if (Script.runtime != "V8") {
            warn("Frida's JavaScript runtime is not V8 (--runtime=v8). Proceed with caution.");
        }

        if (Process.platform == "darwin") {
            let il2cppModuleName = Process.findModuleByAddress(Module.findExportByName(null, "il2cpp_init") || NULL)?.name;
            let unityModuleName = il2cppModuleName;

            if (il2cppModuleName == undefined) {
                unityModuleName = await forModule("UnityFramework", "UnityPlayer.dylib");
                il2cppModuleName = await forModule("UnityFramework", "GameAssembly.dylib");
            }

            Reflect.defineProperty(Unity, "moduleName", { value: unityModuleName });
            Reflect.defineProperty(Il2Cpp, "moduleName", { value: il2cppModuleName });
        } else {
            await forModule(Unity.moduleName);
            await forModule(this.moduleName);
        }

        if (Il2Cpp.Api._getCorlib().isNull()) {
            await new Promise<void>(resolve => {
                const interceptor = Interceptor.attach(Il2Cpp.Api._init, {
                    onLeave() {
                        interceptor.detach();
                        setImmediate(resolve);
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
            .catch(error => {
                if (error.fromIl2CppModule) {
                    (globalThis as any).console.log(error.stack);
                } else {
                    throw error;
                }
            });
    }
}

Reflect.set(globalThis, "Il2Cpp", Il2CppBase);

declare global {
    class Il2Cpp extends Il2CppBase {}
}
