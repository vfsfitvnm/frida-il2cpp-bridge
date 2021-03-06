import { cache } from "decorator-cache-getter";
import { Api } from "../api";
import { getOrNull } from "../utils";
import { Il2CppClass } from "./class";
import { NativeStruct } from "../native-struct";
import { nonNullHandle } from "../decorators";

/**
 * Represents a `Il2CppGenericClass`.
 */
@nonNullHandle
export class Il2CppGenericClass extends NativeStruct {
    /**
     * @return Its class.
     */
    @cache get cachedClass() {
        return getOrNull(Api._genericClassGetCachedClass(this.handle), Il2CppClass);
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
