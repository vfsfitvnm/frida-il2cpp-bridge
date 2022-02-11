import { cache } from "decorator-cache-getter";
import { platformNotSupported } from "../utils/console";
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

    /** */
    @cache
    static get applicationDataPath(): string {
        const get_persistentDataPath = this.internalCall("UnityEngine.Application::get_persistentDataPath", "pointer", [])!;
        return new Il2Cpp.String(get_persistentDataPath()).content!;
    }

    /** */
    @cache
    static get applicationIdentifier(): string | null {
        const get_identifier =
            Il2Cpp.internalCall("UnityEngine.Application::get_identifier", "pointer", []) ??
            Il2Cpp.internalCall("UnityEngine.Application::get_bundleIdentifier", "pointer", []);

        return get_identifier ? new Il2Cpp.String(get_identifier()).content : null;
    }

    /** Gets the version of the application */
    @cache
    static get applicationVersion(): string | null {
        const get_version = Il2Cpp.internalCall("UnityEngine.Application::get_version", "pointer", []);
        return get_version ? new Il2Cpp.String(get_version()).content : null;
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
    static dump(): Pick<Il2Cpp.Dumper, "directoryPath" | "fileName" | "classes"> {
        return new Il2Cpp.Dumper();
    }

    /** Frees memory. */
    static free(pointer: NativePointerValue): void {
        return Il2Cpp.Api._free(pointer);
    }

    /** @internal Waits for Unity and Il2Cpp native libraries to be loaded and initialized. */
    private static async initialize(): Promise<void> {
        if (Process.platform == "darwin") {
            let il2cppModuleName = Process.findModuleByAddress(Module.findExportByName(null, "il2cpp_init") || NULL)?.name;

            if (il2cppModuleName == undefined) {
                il2cppModuleName = await forModule("UnityFramework", "GameAssembly.dylib");
            }

            Reflect.defineProperty(Il2Cpp, "moduleName", { value: il2cppModuleName });
        } else {
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

    /** */
    static internalCall<R extends NativeFunctionReturnType, A extends NativeFunctionArgumentType[] | []>(
        name: string,
        retType: R,
        argTypes: A
    ) {
        const handle = Il2Cpp.Api._resolveInternalCall(Memory.allocUtf8String(name));
        return handle.isNull() ? null : new NativeFunction<R, A>(handle, retType, argTypes);
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
                } finally {
                    if (isForeignThread) {
                        thread?.detach();
                    }
                }
            })
            .catch(e =>
                Script.nextTick(() => {
                    throw e;
                })
            );
    }

    /** Creates a new `Il2Cpp.Tracer` instance. */
    static trace(): Pick<Il2Cpp.Tracer, "domain" | "assemblies" | "classes" | "methods"> {
        return new Il2Cpp.Tracer();
    }
}

Reflect.set(globalThis, "Il2Cpp", Il2CppBase);

declare global {
    class Il2Cpp extends Il2CppBase {}
}
