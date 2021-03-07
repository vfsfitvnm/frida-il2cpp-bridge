import { cache } from "decorator-cache-getter";

import { Api } from "il2cpp/api";
import { nonNullHandle, since } from "il2cpp/decorators";
import { NativeStruct } from "il2cpp/native-struct";

import { _Il2CppImage } from "./image";

/**
 * Represents a `Il2CppAssembly`.
 * ```typescript
 * const mscorlibAssembly = Il2Cpp.domain.assemblies.mscorlib;
 * assert(mscorlibAssembly.name == "mscorlib");
 * ```
 */
@nonNullHandle
export class _Il2CppAssembly extends NativeStruct {
    /**
     * @return Its image.
     */
    @cache get image() {
        return new _Il2CppImage(Api._assemblyGetImage(this.handle));
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
