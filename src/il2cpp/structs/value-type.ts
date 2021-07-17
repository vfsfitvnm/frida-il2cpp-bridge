import { cache } from "decorator-cache-getter";

import { addLevenshtein, filterMap } from "../../utils/record";

import { Api } from "../api";
import { NativeStruct } from "../../utils/native-struct";
import { injectToIl2Cpp } from "../decorators";

@injectToIl2Cpp("ValueType")
class Il2CppValueType extends NativeStruct {
    constructor(handle: NativePointer, readonly klass: Il2Cpp.Class) {
        super(handle);
    }

    get class(): Il2Cpp.Class {
        return this.klass;
    }

    @cache
    get fields(): Readonly<Record<string, Il2Cpp.WithValue>> {
        return addLevenshtein(
            filterMap(
                this.class.fields,
                (field: Il2Cpp.Field) => !field.isStatic,
                (field: Il2Cpp.Field) => field.asHeld(this.handle.add(field.offset).sub(Il2Cpp.Object.headerSize))
            )
        );
    }

    box(): Il2Cpp.Object {
        return new Il2Cpp.Object(Api._valueBox(this.class.handle, this.handle));
    }
}
