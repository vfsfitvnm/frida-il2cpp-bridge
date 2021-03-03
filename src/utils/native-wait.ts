import { platformNotSupported } from "./helpers";

/**
 * @internal
 * It waits for a `Module` to be loaded, if necessary.
 * (e.g. before `DT_INIT` and `DT_INIT_ARRAY` on Android).
 * @param moduleName The name of the target module.
 */
export function forModule(moduleName: string) {
    return new Promise<Module>(resolve => {
        const module = Process.findModuleByName(moduleName);
        if (module) {
            resolve(module);
            return;
        }

        let targets = getTargets();
        getTargets = () => targets;

        if (isAndroidAbove6_0) {
            const interceptor = Interceptor.attach(targets[0].address, {
                onLeave(returnValue) {
                    if (!returnValue.readUtf8String()?.endsWith(moduleName)) return;
                    setTimeout(() => {
                        interceptor.detach();
                        // bionic/linker/linker_phdr.cpp:170: Load CHECK 'did_read_' failed
                    });
                    resolve(Process.getModuleByName(moduleName));
                }
            });
        } else if (isAndroidAbove4_4) {
            const interceptor = Interceptor.attach(targets[0].address, {
                onEnter(args) {
                    this.modulePath = args[0].readPointer().add(0).readUtf8String();
                },
                onLeave() {
                    if (!this.modulePath.endsWith(moduleName)) return;
                    setTimeout(() => {
                        interceptor.detach();
                    });
                    resolve(Process.getModuleByName(moduleName));
                }
            });
        } else if (isWindows) {
            const interceptors = targets.map(target =>
                Interceptor.attach(target.address, {
                    onEnter(args) {
                        this.modulePath = target.name.endsWith("A") ? args[0].readAnsiString() : args[0].readUtf16String();
                    },
                    onLeave() {
                        if (!this.modulePath.endsWith(moduleName)) return;
                        setTimeout(() => interceptors.forEach(i => i.detach()));
                        resolve(Process.getModuleByName(moduleName));
                    }
                })
            );
        } else if (isDarwin) {
            const interceptor = Interceptor.attach(targets[0].address, {
                onEnter(args) {
                    this.modulePath = args[0].readUtf8String();
                },
                onLeave(returnValue) {
                    if (returnValue.isNull() || !this.modulePath || this.modulePath != moduleName) return;
                    setTimeout(() => interceptor.detach());
                    resolve(Process.getModuleByName(moduleName));
                }
            });
        }
    });
}

const isAndroid = (() => {
    try {
        const _ = Java.androidVersion;
        return true;
    } catch (e) {
        return false;
    }
})();
const isAndroidAbove6_0 = isAndroid && ["11", "10", "9", "8.1", "8.0", "7.1", "7.0", "6.0"].includes(Java.androidVersion);
const isAndroidAbove5_1 = isAndroid && ["5.1.1", "5.1"].includes(Java.androidVersion);
const isAndroidAbove4_4 = isAndroid && ["5.0.2", "5.0.1", "4.4.4", "4.4.3", "4.4.2", "4.4.1", "4.4"].includes(Java.androidVersion);

const isWindows = Process.platform == "windows";
const isDarwin = Process.platform == "darwin";

let getTargets = (): (ModuleExportDetails | ModuleSymbolDetails)[] => {
    if (isAndroid) {
        if (!isAndroidAbove6_0 && !isAndroidAbove5_1 && !isAndroidAbove4_4) {
            throw new Error(`Android version ${Java.androidVersion} is not supported.`);
        }
        const responsible = Process.getModuleByName(Process.pointerSize == 4 ? "linker" : "linker64");
        const targetName = isAndroidAbove6_0 ? "get_realpath" : isAndroidAbove5_1 ? "PrelinkImage" : "soinfo_link_image";
        return [responsible.enumerateSymbols().find(e => e.name.includes(targetName))!];
    } else if (isWindows) {
        const responsible = Process.getModuleByName("kernel32.dll");
        const targets = ["LoadLibraryA", "LoadLibraryExA", "LoadLibraryW", "LoadLibraryExW"];
        return responsible.enumerateExports().filter(e => targets.includes(e.name));
    } else if (isDarwin) {
        const responsible = Process.getModuleByName("libdyld.dylib");
        return [responsible.enumerateExports().find(e => e.name == "dlopen")!];
    }

    platformNotSupported();
};
