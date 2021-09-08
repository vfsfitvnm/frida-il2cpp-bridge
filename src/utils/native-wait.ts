import { cache } from "decorator-cache-getter";

import { platformNotSupported } from "./console";

type StringEncoding = "utf8" | "utf16" | "ansi";

class Target {
    readonly address: NativePointer;

    private constructor(responsible: string | null, name: string, readonly stringEncoding: StringEncoding) {
        this.address = Module.findExportByName(responsible, name) ?? NULL;
    }

    @cache
    static get targets(): Target[] {
        function info(): [string | null, ...[string, StringEncoding][]] {
            switch (Process.platform) {
                case "linux":
                    try {
                        const _ = Java.androidVersion;
                        return ["libdl.so", ["dlopen", "utf8"], ["android_dlopen_ext", "utf8"]];
                    } catch (e) {
                        return [null, ["dlopen", "utf8"]];
                    }
                case "darwin":
                    return ["libdyld.dylib", ["dlopen", "utf8"]];
                case "windows":
                    const ll = "LoadLibrary";
                    return ["kernel32.dll", [`${ll}W`, "utf16"], [`${ll}ExW`, "utf16"], [`${ll}A`, "ansi"], [`${ll}ExA`, "ansi"]];
                case "qnx":
                default:
                    platformNotSupported();
            }
        }

        const [responsible, ...targets] = info();
        return targets.map(([name, encoding]) => new Target(responsible, name, encoding)).filter(target => !target.address.isNull());
    }

    readString(pointer: NativePointer): string | null {
        switch (this.stringEncoding) {
            case "utf8":
                return pointer.readUtf8String();
            case "utf16":
                return pointer.readUtf16String();
            case "ansi":
                return pointer.readAnsiString();
        }
    }
}

/** @internal */
export function forModule(moduleName: string): Promise<void> {
    return new Promise<void>(resolve => {
        const module = Process.findModuleByName(moduleName);
        if (module != null) {
            resolve();
        } else {
            const interceptors = Target.targets.map(target =>
                Interceptor.attach(target.address, {
                    onEnter(args: InvocationArguments) {
                        this.modulePath = target.readString(args[0]) || "";
                    },
                    onLeave(returnValue: InvocationReturnValue) {
                        if (!returnValue.isNull() && this.modulePath.endsWith(moduleName)) {
                            setTimeout(() => interceptors.forEach(i => i.detach()));
                            resolve();
                        }
                    }
                })
            );
        }
    });
}
