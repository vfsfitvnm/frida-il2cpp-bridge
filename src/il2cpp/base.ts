import { cache } from "decorator-cache-getter";
import Versioning from "versioning";
import { inform, ok, raise } from "../utils/console";
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

        raise(`${Process.platform} is not supported yet`);
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
            this.internalCall("UnityEngine.Application::get_identifier", "pointer", []) ??
            this.internalCall("UnityEngine.Application::get_bundleIdentifier", "pointer", []);

        return get_identifier ? new Il2Cpp.String(get_identifier()).content : null;
    }

    /** Gets the version of the application */
    @cache
    static get applicationVersion(): string | null {
        const get_version = this.internalCall("UnityEngine.Application::get_version", "pointer", []);
        return get_version ? new Il2Cpp.String(get_version()).content : null;
    }

    /** Gets the attached threads. */
    static get attachedThreads(): Il2Cpp.Thread[] {
        const array: Il2Cpp.Thread[] = [];

        const sizePointer = Memory.alloc(Process.pointerSize);
        const startPointer = Il2Cpp.Api._threadGetAllAttachedThreads(sizePointer);

        const size = sizePointer.readInt();

        for (let i = 0; i < size; i++) {
            array.push(new Il2Cpp.Thread(startPointer.add(i * Process.pointerSize).readPointer()));
        }

        return array;
    }

    /** Gets the current attached thread, if any. */
    static get currentThread(): Il2Cpp.Thread | null {
        const handle = Il2Cpp.Api._threadCurrent();
        return handle.isNull() ? null : new Il2Cpp.Thread(handle);
    }

    /** Gets the Il2Cpp module as a Frida module. */
    @cache
    static get module(): Module {
        return Process.getModuleByName(this.moduleName);
    }

    /** Gets the Unity version of the current application. */
    @cache
    static get unityVersion(): string {
        const get_unityVersion = this.internalCall("UnityEngine.Application::get_unityVersion", "pointer", []);

        if (get_unityVersion == null) {
            raise("couldn't determine the Unity version, please specify it manually");
        }

        return new Il2Cpp.String(get_unityVersion()).content!;
    }

    /** @internal */
    @cache
    static get unityVersionIsBelow201830(): boolean {
        return Versioning.lt(this.unityVersion, "2018.3.0");
    }

    /** Allocates the given amount of bytes. */
    static alloc(size: number | UInt64 = Process.pointerSize): NativePointer {
        return Il2Cpp.Api._alloc(size);
    }

    /** Dumps the application. */
    static dump(fileName?: string, path?: string): void {
        fileName = fileName ?? `${Il2Cpp.applicationIdentifier ?? "unknown"}_${Il2Cpp.applicationVersion ?? "unknown"}.cs`;

        const destination = `${path ?? Il2Cpp.applicationDataPath}/${fileName}`;
        const file = new File(destination, "w");

        for (const assembly of Il2Cpp.Domain.assemblies) {
            inform(`dumping ${assembly.name}...`);

            for (const klass of assembly.image.classes) {
                file.write(`${klass}\n\n`);
            }
        }

        file.flush();
        file.close();
        ok(`dump saved to ${destination}`);
    }

    /** Frees memory. */
    static free(pointer: NativePointerValue): void {
        return Il2Cpp.Api._free(pointer);
    }

    /** @internal Waits for Unity and Il2Cpp native libraries to be loaded and initialized. */
    private static async initialize(): Promise<void> {
        if (Process.platform == "darwin") {
            let il2cppModuleName = Process.findModuleByAddress(Module.findExportByName(null, "il2cpp_init") ?? NULL)?.name;

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

    /** Schedules a callback on the Il2Cpp initializer thread. */
    static async scheduleOnInitializerThread<T>(block: () => T | Promise<T>): Promise<T> {
        return new Promise<T>(resolve => {
            const listener = Interceptor.attach(Il2Cpp.Api._threadCurrent, () => {
                listener.detach();
                const result = block();
                setImmediate(() => resolve(result));
            });
        });
    }

    /** Attaches the caller thread to Il2Cpp domain and executes the given block.  */
    static async perform<T>(block: () => T | Promise<T>): Promise<T> {
        await this.initialize();

        let thread = this.currentThread;
        const isForeignThread = thread == null;

        if (thread == null) {
            thread = Il2Cpp.Domain.attach();
        }

        try {
            return block();
        } catch (e: any) {
            (globalThis as any).console.log(e);
            throw e;
        } finally {
            if (isForeignThread) {
                thread.detach();
            }
        }
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
