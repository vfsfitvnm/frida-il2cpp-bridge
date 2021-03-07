import { cache } from "decorator-cache-getter";

import { filterAndMap } from "../../utils/accessor";

import { Api } from "../api";
import { NativeStruct } from "../native-struct";

import { _Il2CppClass } from "./class";
import { _Il2CppObject } from "./object";

/**
 * Abstraction over the a value type (`struct`).
 * NOTE: you may experience few problems with value types.
 * ```typescript
 * const engine = Il2Cpp.domain.assemblies["UnityEngine.CoreModule"].image;
 * const Vector2 = engine.classes["UnityEngine.Vector2"];
 * //
 * const vec = Vector2.fields.positiveInfinityVector.value as Il2Cpp.ValueType;
 * //
 * assert(vec.class.type.name == "UnityEngine.Vector2");
 * //
 * assert(vec.fields.x.value == Infinity);
 * assert(vec.fields.y.value == Infinity);
 * ```
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
    get class() {
        return this.klass;
    }

    /**
     * @return Its fields.
     */
    @cache get fields() {
        return this.class.fields[filterAndMap](
            field => field.isInstance,
            field => field.asHeld(this.handle.add(field.offset).sub(_Il2CppObject.headerSize))
        );
    }

    /**
     * See {@link _Il2CppObject.unbox} for an example.
     * @return The boxed value type.
     */
    box() {
        return new _Il2CppObject(Api._valueBox(this.klass.handle, this.handle));
    }
}
