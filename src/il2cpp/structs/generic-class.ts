import { cache } from "decorator-cache-getter";

import { NonNullNativeStruct } from "../../utils/native-struct";
import { getOrNull } from "../../utils/utils";

/** Represents a `Il2CppGenericClass`. */
class Il2CppGenericClass extends NonNullNativeStruct {
    /** */
    @cache
    get cachedClass(): Il2Cpp.Class {
        return new Il2Cpp.Class(Il2Cpp.Api._genericClassGetCachedClass(this));
    }

    /** */
    @cache
    get classGenericInstance(): Il2Cpp.GenericInstance | null {
        return getOrNull(Il2Cpp.Api._genericClassGetClassGenericInstance(this), Il2Cpp.GenericInstance);
    }

    /** */
    @cache
    get methodGenericInstance(): Il2Cpp.GenericInstance | null {
        return getOrNull(Il2Cpp.Api._genericClassGetMethodGenericInstance(this), Il2Cpp.GenericInstance);
    }
}

Il2Cpp.GenericClass = Il2CppGenericClass;

declare global {
    namespace Il2Cpp {
        class GenericClass extends Il2CppGenericClass {}
    }
}
