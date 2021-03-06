import { cache } from "decorator-cache-getter";
import { Api } from "../api";
import { Il2CppImage } from "./image";
import { nonNullHandle, since } from "../decorators";
import { NativeStruct } from "../native-struct";

/**
 * Represents a `Il2CppAssembly`.
 * ```typescript
 * const mscorlibAssembly = Il2Cpp.domain.assemblies.mscorlib;
 * assert(mscorlibAssembly.name == "mscorlib");
 * ```
 */
@nonNullHandle
export class Il2CppAssembly extends NativeStruct {
    /**
     * @return Its image.
     */
    @cache get image() {
        return new Il2CppImage(Api._assemblyGetImage(this.handle));
    }

    /**
     * @return Its name.
     */
    @cache
    @since("2018.1.0")
    get name() {
        return Api._assemblyGetName(this.handle)!;
    }
}
