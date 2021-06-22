import { cache } from "decorator-cache-getter";

import { Accessor, filterAndMap} from "../../utils/accessor";

import { Api } from "../api";
import { Valuable } from "../interfaces";
import { NativeStruct } from "../native-struct";

import { _Il2CppClass } from "./class";
import { _Il2CppObject } from "./object";

/**
 * Abstraction over the a value type (`struct`).
 * NOTE: you may experience few problems with value types.
 */
export class _Il2CppValueType extends NativeStruct {
    constructor(handle: NativePointer, readonly klass: _Il2CppClass) {
        super(handle);
    }

    /**
     * NOTE: the class is hardcoded when a new instance is created.\
     * It's not completely reliable.
     * @return Its class.
     */
    get class(): _Il2CppClass {
        return this.klass;
    }

    /**
     * @return Its fields.
     */
    @cache
    get fields(): Accessor<Valuable> {
        return this.class.fields[filterAndMap](
            field => field.isInstance,
            field => field.asHeld(this.handle.add(field.offset).sub(_Il2CppObject.headerSize))
        );
    }

    /**
     * See {@link _Il2CppObject.unbox} for an example.
     * @return The boxed value type.
     */
    box(): _Il2CppObject {
        return new _Il2CppObject(Api._valueBox(this.klass.handle, this.handle));
    }
}
