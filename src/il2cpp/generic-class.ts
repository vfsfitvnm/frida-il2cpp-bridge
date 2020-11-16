import Api from "./api";
import { lazy } from "../utils/decorators";
import { getOrNull } from "../utils/helpers";
import Il2CppClass from "./class";
import { raise } from "../utils/console";

/** @internal */
export default class Il2CppGenericClass {
    constructor(readonly handle: NativePointer) {
        if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
    }

    @lazy get cachedClass() {
        return getOrNull(Api._genericClassGetCachedClass(this.handle), Il2CppClass);
    }
}
