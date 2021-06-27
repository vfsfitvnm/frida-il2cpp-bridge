import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { getOrNull, NativeStructNotNull } from "../../utils/native-struct";
import { injectToIl2Cpp } from "../decorators";

@injectToIl2Cpp("GenericClass")
class Il2CppGenericClass extends NativeStructNotNull {
    @cache
    get cachedClass(): Il2Cpp.Class | null {
        return getOrNull(Api._genericClassGetCachedClass(this.handle), Il2Cpp.Class);
    }

    // // @cache get types() {
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

    // // @cache get typesCount() {
    //     return Api._genericClassGetTypesCount(this.handle);
    // }
}
