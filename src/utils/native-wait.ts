/** @internal */
interface ResolvedExport {
    handle: NativePointer;
    readString: (handle: NativePointer) => string | null;
}

/** @internal */
function forModule(...moduleNames: string[]): Promise<Module> {
    function find(
        moduleName: string | null,
        name: string,
        readString: (handle: NativePointer) => string | null = _ => _.readUtf8String()
    ): ResolvedExport | undefined {
        const handle = Module.findExportByName(moduleName, name) ?? NULL;
        if (!handle.isNull()) {
            return { handle, readString };
        }
    }

    return new Promise<Module>(resolve => {
        for (const moduleName of moduleNames) {
            const module = Process.findModuleByName(moduleName);
            if (module != null) {
                resolve(module);
                return;
            }
        }

        let targets: (ResolvedExport | undefined)[] = [];

        switch (Process.platform) {
            case "linux":
                if (Android.apiLevel == null) {
                    targets = [find(null, "dlopen")];
                    break;
                }

                // A5: device reboot, can't hook symbols
                // A6, A7: __dl_open
                // A8, A8.1: __dl__Z8__dlopenPKciPKv
                // A9, A10, A12, A13: __dl___loader_dlopen
                targets = (Process.findModuleByName("linker64") ?? Process.getModuleByName("linker"))
                    .enumerateSymbols()
                    .filter(_ => ["__dl___loader_dlopen", "__dl__Z8__dlopenPKciPKv", "__dl_open"].includes(_.name))
                    .map(_ => ({ handle: _.address, readString: _ => _.readCString() }));
                break;
            case "darwin":
                targets = [find("libdyld.dylib", "dlopen")];
                break;
            case "windows":
                targets = [
                    find("kernel32.dll", "LoadLibraryW", _ => _.readUtf16String()),
                    find("kernel32.dll", "LoadLibraryExW", _ => _.readUtf16String()),
                    find("kernel32.dll", "LoadLibraryA", _ => _.readAnsiString()),
                    find("kernel32.dll", "LoadLibraryExA", _ => _.readAnsiString())
                ];
                break;
        }

        targets = targets.filter(_ => _);

        if (targets.length == 0) {
            raise(`there are no targets to hook the loading of \x1b[3m${moduleNames}\x1b[0m, please file a bug`);
        }

        const timeout = setTimeout(() => {
            for (const moduleName of moduleNames) {
                const module = Process.findModuleByName(moduleName);
                if (module != null) {
                    warn(`\x1b[3m${module.name}\x1b[0m has been loaded, but such event hasn't been detected - please file a bug`);
                    clearTimeout(timeout);
                    interceptors.forEach(_ => _.detach());
                    resolve(module);
                    return;
                }
            }

            warn(`10 seconds have passed and \x1b[3m${moduleNames}\x1b[0m has not been loaded yet, is the app running?`);
        }, 10000);

        const interceptors = targets.map(_ =>
            Interceptor.attach(_!.handle, {
                onEnter(args: InvocationArguments) {
                    this.modulePath = _!.readString(args[0]) ?? "";
                },
                onLeave(_: InvocationReturnValue) {
                    for (const moduleName of moduleNames) {
                        if (this.modulePath.endsWith(moduleName)) {
                            const module = Process.findModuleByName(this.modulePath);

                            if (module != null) {
                                setImmediate(() => {
                                    clearTimeout(timeout);
                                    interceptors.forEach(_ => _.detach());
                                });
                                resolve(module);
                                break;
                            }
                        }
                    }
                }
            })
        );
    });
}
