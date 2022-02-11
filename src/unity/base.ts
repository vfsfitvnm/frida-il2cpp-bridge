import { cache } from "decorator-cache-getter";
import { Version } from "../utils/version";

/** */
class UnityBase {
    /** @internal */
    @cache
    static get isBelow2018_3_0(): boolean {
        return this.version.isBelow("2018.3.0");
    }

    /** Determines whether the Unity version is fully supported by this module. */
    @cache
    static get mayBeUnsupported(): boolean {
        return this.version.isBelow("5.3.0") || this.version.isEqualOrAbove("2022.2.0");
    }

    /** Gets the Unity version of the current application. */
    @cache
    static get version(): Version {
        Version.pattern = /(20\d{2}|\d)\.(\d)\.(\d{1,2})([abcfp]|rc){0,2}\d?/;

        const get_unityVersion = Il2Cpp.Api._resolveInternalCall(Memory.allocUtf8String("UnityEngine.Application::get_unityVersion"));
        const get_unityVersionNative = new NativeFunction(get_unityVersion, "pointer", []);
        return new Version(new Il2Cpp.String(get_unityVersionNative()).content!);
    }
}

Reflect.set(globalThis, "Unity", UnityBase);

declare global {
    class Unity extends UnityBase {}
}
