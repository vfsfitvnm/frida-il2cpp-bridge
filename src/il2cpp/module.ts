namespace Il2Cpp {
    /** @internal Gets the Il2Cpp module name. */
    export declare const moduleName: string;
    getter(Il2Cpp, "moduleName", () => {
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
    });

    /** Gets the Il2Cpp module as a Frida module. */
    export declare const module: Module;
    // prettier-ignore
    getter(Il2Cpp, "module", () => {
        return Process.getModuleByName(moduleName);
    }, lazy);

    /** @internal Waits for Unity and Il2Cpp native libraries to be loaded and initialized. */
    export async function initialize(): Promise<void> {
        if (Process.platform == "darwin") {
            Reflect.defineProperty(Il2Cpp, "moduleName", {
                value: DebugSymbol.fromName("il2cpp_init").moduleName ?? (await forModule("UnityFramework", "GameAssembly.dylib"))
            });
        } else {
            await forModule(Il2Cpp.moduleName);
        }

        if (Il2Cpp.api.getCorlib().isNull()) {
            await new Promise<void>(resolve => {
                const interceptor = Interceptor.attach(Il2Cpp.api.initialize, {
                    onLeave() {
                        interceptor.detach();
                        setImmediate(resolve);
                    }
                });
            });
        }
    }
}
