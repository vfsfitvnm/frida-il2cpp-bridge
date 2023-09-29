namespace Il2Cpp {
    /** Gets the Il2Cpp module as a Frida module. */
    export declare const module: Module;
    getter(Il2Cpp, "module", () => {
        const [moduleName, fallback] = getExpectedModuleNames();
        return Process.findModuleByName(moduleName) ?? Process.getModuleByName(fallback);
    });

    /** @internal Waits for Unity and Il2Cpp native libraries to be loaded and initialized. */
    export async function initialize(blocking = false): Promise<boolean> {
        Reflect.defineProperty(Il2Cpp, "module", {
            // prettier-ignore
            value: Process.platform == "darwin"
                ? Process.findModuleByAddress(DebugSymbol.fromName("il2cpp_init").address) 
                    ?? await forModule(...getExpectedModuleNames())
                : await forModule(...getExpectedModuleNames())
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

    function getExpectedModuleNames(): string[] {
        if ((globalThis as any).IL2CPP_MODULE_NAME) {
            return [(globalThis as any).IL2CPP_MODULE_NAME];
        }

        switch (Process.platform) {
            case "linux":
                return [Android.apiLevel ? "libil2cpp.so" : "GameAssembly.so"];
            case "windows":
                return ["GameAssembly.dll"];
            case "darwin":
                return ["UnityFramework", "GameAssembly.dylib"];
        }

        raise(`${Process.platform} is not supported yet`);
    }
}
