import { cache } from "decorator-cache-getter";

import { Api } from "il2cpp/api";
import { nonNullHandle } from "il2cpp/decorators";
import { NativeStruct } from "il2cpp/native-struct";
import { getOrNull } from "il2cpp/utils";

import { _Il2CppClass } from "./class";

/**
 * Represents a `Il2CppGenericClass`.
 */
@nonNullHandle
export class _Il2CppGenericClass extends NativeStruct {
    /**
     * @return Its class.
     */
    @cache get cachedClass() {
        return getOrNull(Api._genericClassGetCachedClass(this.handle), _Il2CppClass);
    }

    // /**
    //  * @return Its types.
    //  */
    // @cache get types() {
    //     const types: Il2CppType[] = [];
    //     const count = this.typesCount;
    //     const start = Api._genericClassGetTypes(this.handle);
    //
    //     for (let i = 0; i < count; i++) {
    //         const pointer = start.add(i * Process.pointerSize).readPointer();
    //         const type = new Il2CppType(pointer);
    //         types.push(type);
    //     }
    //     return types;
    // }

    // /**
    //  * @return Its types count.
    //  */
    // @cache get typesCount() {
    //     return Api._genericClassGetTypesCount(this.handle);
    // }
}
