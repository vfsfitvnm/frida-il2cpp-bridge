import { cache } from "decorator-cache-getter";
import { platformNotSupported, raise, warn } from "../utils/console";
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
        this.initialize()
            .then(() => {
                let thread = Il2Cpp.Thread.current;
                const isForeignThread = thread == null;

                if (isForeignThread) {
                    thread = Il2Cpp.Domain.attach();
                }

                try {
                    block();
                } catch (error: any) {
                    if (isForeignThread) {
                        thread?.detach();
                    }

                    if (error.fromIl2CppModule) {
                        (globalThis as any).console.log(error.stack);
                    } else {
                        throw error;
                    }
                }
            })
            .catch(error =>
                Script.nextTick(() => {
                    throw error;
                })
            );
    }

    /** Tries to execute the given block and prints the underlying C# (C++) exception. */
    static try<T>(block: () => T): T {
        try {
            return block();
        } catch (error: any) {
            if (error.message != "abort was called") {
                throw error;
            }

            const exception = Il2Cpp.Api._cxaGetGlobals().readPointer();
            const dummyException = Il2Cpp.Api._cxaAllocateException(Process.pointerSize);

            try {
                Il2Cpp.Api._cxaThrow(dummyException, NULL, NULL);
            } catch (e) {
                const dummyExceptionHeader = Il2Cpp.Api._cxaGetGlobals().readPointer();

                for (let i = 0; i < 256; i++) {
                    if (dummyExceptionHeader.add(i).equals(dummyException)) {
                        Il2Cpp.Api._cxaFreeException(dummyException);

                        raise(new Il2Cpp.Object(exception.add(i).readPointer()).toString()!);
                    }
                }
            }

            throw error;
        }
    }
}

Reflect.set(globalThis, "Il2Cpp", Il2CppBase);

declare global {
    class Il2Cpp extends Il2CppBase {}
}
