import { cache } from "decorator-cache-getter";

import { Accessor, filterAndMap } from "../../utils/accessor";

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
    get fields(): Accessor<Il2Cpp.WithValue> {
        return this.class.fields[filterAndMap](
            field => !field.isStatic,
            field => field.asHeld(this.handle.add(field.offset).sub(Il2Cpp.Object.headerSize))
        );
    }

    box(): Il2Cpp.Object {
        return new Il2Cpp.Object(Api._valueBox(this.class.handle, this.handle));
    }
}
