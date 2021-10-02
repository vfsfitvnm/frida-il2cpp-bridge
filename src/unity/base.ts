import { cache } from "decorator-cache-getter";
import { platformNotSupported, raise } from "../utils/console";
import { Version } from "../utils/version";

/** */
class UnityBase {
    /** Gets the Unity module name. */
    static get moduleName(): string {
        switch (Process.platform) {
            case "linux":
                try {
                    const _ = Java.androidVersion;
                    return "libunity.so";
                } catch (e) {
                    return "UnityPlayer.so";
                }
            case "windows":
                return "UnityPlayer.dll";
            case "darwin":
                try {
                    return "UnityFramework";
                } catch (e) {
                    return "UnityPlayer.dylib";
                }
        }

        platformNotSupported();
    }

    /** @internal */
    @cache
    static get isBelow2018_3_0(): boolean {
        return this.version.isBelow("2018.3.0");
    }

    /** Determines whether the Unity version is fully supported by this module. */
    @cache
    static get mayBeUnsupported(): boolean {
        return this.version.isBelow("5.3.0") || this.version.isEqualOrAbove("2021.2.0");
    }

    /** Gets the Unity version of the current application. */
    @cache
    static get version(): Version {
        Version.pattern = /(20\d{2}|\d)\.(\d)\.(\d{1,2})([abcfp]|rc){0,2}\d?/;

        const module = Process.getModuleByName(this.moduleName);
        const ranges = [...module.enumerateRanges("r--"), Process.getRangeByAddress(module.base)];

        for (const range of ranges) {
            const scan = Memory.scanSync(range.base, range.size, "45787065637465642076657273696f6e3a")[0];

            if (scan != undefined) {
                return new Version(scan.address.readUtf8String()!);
            }
        }

        raise("Couldn't obtain the Unity version. Please open an issue.");
    }
}

Reflect.set(globalThis, "Unity", UnityBase);

declare global {
    class Unity extends UnityBase {}
}
