namespace Il2Cpp {
    /** @internal Gets the Il2Cpp module name. */
    export declare const moduleName: string;
    getter(Il2Cpp, "moduleName", () => {
        switch (Process.platform) {
            case "linux":
                return Android.apiLevel ? "libil2cpp.so" : "GameAssembly.so";
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
    });

    /** Gets the Il2Cpp module as a Frida module. */
    export declare const module: Module;
    // prettier-ignore
    getter(Il2Cpp, "module", () => {
        return Process.getModuleByName(moduleName);
    }, lazy);

    /** @internal Waits for Unity and Il2Cpp native libraries to be loaded and initialized. */
    export async function initialize(blocking = false): Promise<boolean> {
        Reflect.defineProperty(Il2Cpp, "module", {
            // prettier-ignore
            value: Process.platform == "darwin"
                ? Process.findModuleByAddress(DebugSymbol.fromName("il2cpp_init").address) 
                    ?? await forModule("UnityFramework", "GameAssembly.dylib")
                : await forModule(Il2Cpp.moduleName)
        });

        if (Il2Cpp.api.getCorlib().isNull()) {
            return await new Promise<boolean>(resolve => {
                const interceptor = Interceptor.attach(Il2Cpp.api.initialize, {
                    onLeave() {
                        interceptor.detach();
                        blocking ? resolve(true) : setImmediate(() => resolve(false));
                    }
                });
            });
        }

        return false;
    }
}
