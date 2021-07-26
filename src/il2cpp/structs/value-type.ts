import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

import { NativeStruct } from "../../utils/native-struct";
import { addLevenshtein, filterMap } from "../../utils/record";

@injectToIl2Cpp("ValueType")
class Il2CppValueType extends NativeStruct {
    constructor(handle: NativePointer, readonly klass: Il2Cpp.Class) {
        super(handle);
    }

    get class(): Il2Cpp.Class {
        return this.klass;
    }

    @cache
    get fields(): Readonly<Record<string, Il2Cpp.Field>> {
        return addLevenshtein(
            filterMap(
                this.class.fields,
                (field: Il2Cpp.Field) => !field.isStatic,
                (field: Il2Cpp.Field) => field.withHolder(this)
            )
        );
    }

    box(): Il2Cpp.Object {
        return new Il2Cpp.Object(Api._valueBox(this.class, this));
    }
}
