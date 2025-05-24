namespace Il2Cpp {
    /**
     * Gets the IL2CPP module (a *native library*), that is where the IL2CPP
     * exports will be searched for (see {@link Il2Cpp.exports}).
     *
     * The module is located by its name:
     * - Android: `libil2cpp.so`
     * - Linux: `GameAssembly.so`
     * - Windows: `GameAssembly.dll`
     * - iOS: `UnityFramework`
     * - macOS: `GameAssembly.dylib`
     *
     * On iOS and macOS, IL2CPP exports may be located within a module having
     * a different name.
     *
     * In any case, it is possible to override or set the IL2CPP module name
     * using {@link Il2Cpp.$config.moduleName}:
     * ```ts
     * Il2Cpp.$config.moduleName = "CustomName.dylib";
     *
     * Il2Cpp.perform(() => {
     *     // ...
     * });
     * ```
     */
    export declare const module: Module;
    getter(Il2Cpp, "module", () => {
        return tryModule() ?? raise("Could not find IL2CPP module");
    });

    /**
     * @internal
     * Waits for the IL2CPP native library to be loaded and initialized.
     */
    export async function initialize(blocking = false): Promise<boolean> {
        const module =
            tryModule() ??
            (await new Promise<Module>(resolve => {
                const [moduleName, fallbackModuleName] = getExpectedModuleNames();

                const timeout = setTimeout(() => {
                    warn(`after 10 seconds, IL2CPP module '${moduleName}' has not been loaded yet, is the app running?`);
                }, 10000);

                const moduleObserver = Process.attachModuleObserver({
                    onAdded(module: Module) {
                        if (module.name == moduleName || (fallbackModuleName && module.name == fallbackModuleName)) {
                            clearTimeout(timeout);
                            setImmediate(() => {
                                resolve(module);
                                moduleObserver.detach();
                            });
                        }
                    }
                });
            }));

        Reflect.defineProperty(Il2Cpp, "module", { value: module });

        // At this point, the IL2CPP native library has been loaded, but we
        // cannot interact with IL2CPP until `il2cpp_init` is done.
        // It looks like `il2cpp_get_corlib` returns NULL only when the
        // initialization is not completed yet.
        if (Il2Cpp.exports.getCorlib().isNull()) {
            return await new Promise<boolean>(resolve => {
                const interceptor = Interceptor.attach(Il2Cpp.exports.initialize, {
                    onLeave() {
                        interceptor.detach();
                        blocking ? resolve(true) : setImmediate(() => resolve(false));
                    }
                });
            });
        }

        return false;
    }

    function tryModule(): Module | undefined {
        const [moduleName, fallback] = getExpectedModuleNames();
        const module = (
            Process.findModuleByName(moduleName) ??
            Process.findModuleByName(fallback ?? moduleName) ??
            undefined
        );
        if (module) {
            return module;
        }
        
        if (Process.platform == "darwin") {
            return Process.findModuleByAddress(DebugSymbol.fromName("il2cpp_init").address) ?? undefined;
        }

        return undefined;
    }

    function getExpectedModuleNames(): [string] | [string, string] {
        if (Il2Cpp.$config.moduleName) {
            return [Il2Cpp.$config.moduleName];
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
