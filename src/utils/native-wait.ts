/** @internal */
function forModule(...moduleNames: string[]): Promise<Module> {
    type Encoding = { [K in keyof NativePointer]: K extends `read${infer T}String` ? T : never }[keyof NativePointer];

    return new Promise<Module>(resolve => {
        for (const moduleName of moduleNames) {
            const module = Process.findModuleByName(moduleName);
            if (module != null) {
                resolve(module);
                return;
            }
        }

        let targets: [NativePointer | null | undefined, Encoding][] = [];

        switch (Process.platform) {
            case "linux":
                if (Android.apiLevel == null) {
                    targets = [[Module.findExportByName(null, "dlopen"), "Utf8"]];
                    break;
                }

                const linker = Process.findModuleByName("linker64") ?? Process.findModuleByName("linker");

                if (linker == null) {
                    if (Android.apiLevel >= 31) {
                        targets = [[Module.findExportByName(null, "__loader_dlopen"), "Utf8"]];
                    } else {
                        targets = [
                            [Module.findExportByName("libdl.so", "dlopen"), "Utf8"],
                            [Module?.findExportByName("libdl.so", "android_dlopen_ext"), "Utf8"]
                        ];
                    }
                    break;
                }

                // A5: device reboot, can't hook symbols
                // A6, A7: __dl_open
                // A8, A8.1: __dl__Z8__dlopenPKciPKv
                // A9, A10, A12, A13: __dl___loader_dlopen
                targets = linker
                    .enumerateSymbols()
                    .filter(_ => ["__dl___loader_dlopen", "__dl__Z8__dlopenPKciPKv", "__dl_open"].includes(_.name))
                    .map(_ => [_.address, "C"]);
                break;
            case "darwin":
                targets = [[Module.findExportByName("libdyld.dylib", "dlopen"), "Utf8"]];
                break;
            case "windows":
                targets = [
                    [Module.findExportByName("kernel32.dll", "LoadLibraryW"), "Utf16"],
                    [Module.findExportByName("kernel32.dll", "LoadLibraryExW"), "Utf16"],
                    [Module.findExportByName("kernel32.dll", "LoadLibraryA"), "Ansi"],
                    [Module.findExportByName("kernel32.dll", "LoadLibraryExA"), "Ansi"]
                ];
                break;
        }

        targets = targets.filter(_ => _[0]);

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

        const interceptors = targets.map(([handle, encoding]) =>
            Interceptor.attach(handle!, {
                onEnter(args: InvocationArguments) {
                    this.modulePath = args[0][`read${encoding}String`]() ?? "";
                },
                onLeave(_: InvocationReturnValue) {
                    for (const moduleName of moduleNames) {
                        if (this.modulePath.endsWith(moduleName)) {
                            // Adding a fallback in case Frida cannot find the module by its full path
                            // https://github.com/vfsfitvnm/frida-il2cpp-bridge/issues/547
                            const module = Process.findModuleByName(this.modulePath) ?? Process.findModuleByName(moduleName);

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
