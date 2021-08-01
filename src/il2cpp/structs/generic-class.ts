import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

import { getOrNull, NonNullNativeStruct } from "../../utils/native-struct";

@injectToIl2Cpp("GenericClass")
class Il2CppGenericClass extends NonNullNativeStruct {
    @cache
    get cachedClass(): Il2Cpp.Class {
        return new Il2Cpp.Class(Api._genericClassGetCachedClass(this));
    }

    @cache
    get classGenericInstance(): Il2Cpp.GenericInstance | null {
        return getOrNull(Api._genericClassGetClassGenericInstance(this), Il2Cpp.GenericInstance);
    }

    @cache
    get methodGenericInstance(): Il2Cpp.GenericInstance | null {
        return getOrNull(Api._genericClassGetMethodGenericInstance(this), Il2Cpp.GenericInstance);
    }
}
