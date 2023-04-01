import { cache } from "decorator-cache-getter";
import Versioning from "versioning";
import { inform, ok, raise } from "../utils/console.js";
import { forModule } from "../utils/native-wait.js";

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
        if (Il2Cpp.currentThread == null) {
            raise("only Il2Cpp threads can invoke Il2Cpp.attachedThreads");
        }

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

        if (get_unityVersion != null) {
            return new Il2Cpp.String(get_unityVersion()).content!;
        }

        const versionPattern = /(?:20\d{2}|\d)\.\d\.\d{1,2}([abcfp]|rc){0,2}\d?/;
        const searchPattern = "45 64 69 74 6f 72 ?? 44 61 74 61 ?? 69 6c 32 63 70 70";

        for (const range of this.module.enumerateRanges("r--").concat(Process.getRangeByAddress(this.module.base))) {
            for (let { address } of Memory.scanSync(range.base, range.size, searchPattern)) {
                while (address.readU8() != 0) {
                    address = address.sub(1);
                }

                const match = address.add(1).readCString()?.match(versionPattern)?.[0];

                if (match != undefined) {
                    return match;
                }
            }
        }

        raise("couldn't determine the Unity version, please specify it manually");
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

    /** Creates a new `Il2Cpp.Backtracer` instance. */
    static backtrace(): Pick<Il2Cpp.Backtracer, "accurate" | "fuzzy"> {
        return new Il2Cpp.Backtracer();
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
    static installExceptionListener(targetThread: "current" | "all" = "current"): InvocationListener {
        const threadId = Process.getCurrentThreadId();

        return Interceptor.attach(Il2Cpp.module.getExportByName("__cxa_throw"), function (args) {
            if (targetThread == "current" && this.threadId != threadId) {
                return;
            }

            inform(new Il2Cpp.Object(args[0].readPointer()));
        });
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
    static scheduleOnInitializerThread<T>(block: () => T | Promise<T>): Promise<T> {
        return new Promise<T>(resolve => {
            const listener = Interceptor.attach(Il2Cpp.Api._threadCurrent, () => {
                const currentThreadId = Il2Cpp.currentThread?.id;
                if (currentThreadId != undefined && currentThreadId == Il2Cpp.attachedThreads[0].id) {
                    listener.detach();
                    const result = block();
                    setImmediate(() => resolve(result));
                }
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
            const result = block();
            return result instanceof Promise ? await result : result;
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
    static trace(): Pick<Il2Cpp.Tracer, "detailed" | "domain" | "assemblies" | "classes" | "methods"> {
        return new Il2Cpp.Tracer();
    }
}

Reflect.set(globalThis, "Il2Cpp", Il2CppBase);

declare global {
    class Il2Cpp extends Il2CppBase {}
}
