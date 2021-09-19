import { cache } from "decorator-cache-getter";
import { platformNotSupported, warn } from "../utils/console";
import { forModule } from "../utils/native-wait";

/** */
class Il2CppBase {
    protected constructor() {}

    /** @internal Gets the Il2Cpp module name. */
    private static get moduleName(): string {
        return Process.platform == "linux" ? "libil2cpp.so" : Process.platform == "windows" ? "GameAssembly.dll" : platformNotSupported();
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

        await forModule(Unity.moduleName);
        await forModule(this.moduleName);

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
