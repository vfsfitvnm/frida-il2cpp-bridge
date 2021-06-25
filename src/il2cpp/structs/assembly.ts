import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { nonNullHandle } from "../decorators";
import { NativeStruct } from "../native-struct";
import { unityVersion } from "../variables";

import { _Il2CppImage } from "./image";

/**
 * Represents a `Il2CppAssembly`.
 */
@nonNullHandle
export class _Il2CppAssembly extends NativeStruct {
    /**
     * @return Its image.
     */
    @cache
    get image(): _Il2CppImage {
        return new _Il2CppImage(Api._assemblyGetImage(this.handle));
    }

    /**
     * @return Its name.
     */
    @cache
    get name(): string {
        if (unityVersion.isLegacy) {
            return this.image.name.replace(".dll", "");
        } else {
            return Api._assemblyGetName(this.handle)!;
        }
    }
}