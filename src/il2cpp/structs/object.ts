import { cache } from "decorator-cache-getter";

import { filterAndMap } from "utils/accessor";
import { raise } from "utils/logger";

import { Api } from "il2cpp/api";
import { NativeStruct } from "il2cpp/native-struct";

import { _Il2CppClass } from "./class";
import { _Il2CppValueType } from "./value-type";

/**
 * Represents a `Il2CppObject`.
 * ```typescript
 * const mscorlib = Il2Cpp.domain.assemblies.mscorlib.image;
 * const CoreModule = Il2Cpp.domain.assemblies["UnityEngine.CoreModule"].image;
 * //
 * const OrdinalComparerClass = mscorlib.classes["System.OrdinalComparer"];
 * const Vector2Class = CoreModule.classes["UnityEngine.Vector2"];
 * //
 * const ordinalComparer = Il2Cpp.Object.from(OrdinalComparerClass);
 * assert(ordinalComparer.class.name == "OrdinalComparer");
 * assert(ordinalComparer.base.class.name == "StringComparer");
 * //
 * const vec = Il2Cpp.Object.from(Vector2Class);
 * vec.methods[".ctor"].invoke(36, 4);
 * const vecUnboxed = vec.unbox();
 * assert(vec.fields.x.value == vecUnboxed.fields.x.value);
 * assert(vec.fields.y.value == vecUnboxed.fields.y.value);
 * const vecBoxed = vecUnboxed.box();
 * assert(vecBoxed.fields.x.value == vecUnboxed.fields.x.value);
 * assert(vecBoxed.fields.y.value == vecUnboxed.fields.y.value);
 * assert(!vecBoxed.handle.equals(vec.handle));
 * ```
 */
export class _Il2CppObject extends NativeStruct {
    /** @internal */
    @cache
    static get headerSize() {
        return Api._objectGetHeaderSize();
    }

    /**
     * @return The same object as an instance of its parent.
     */
    @cache get base() {
        if (this.class.parent == null) {
            raise(`Class "${this.class.type.name}" has no parent.`);
        }

        const object = new _Il2CppObject(this.handle);
        Reflect.defineProperty(object, "class", { get: () => this.class.parent! });
        return object;
    }

    /**
     * @return Its class.
     */
    @cache get class() {
        return new _Il2CppClass(Api._objectGetClass(this.handle));
    }

    /**
     * See {@link _Il2CppClass.fields} for an example.
     * @return Its fields.
     */
    @cache get fields() {
        return this.class.fields[filterAndMap](
            field => field.isInstance,
            field => field.asHeld(this.handle.add(field.offset))
        );
    }

    /**
     * See {@link _Il2CppClass.methods} for an example.
     * @return Its methods.
     */
    @cache get methods() {
        return this.class.methods[filterAndMap](
            method => method.isInstance,
            method => method.asHeld(this.handle)
        );
    }

    /**
     * NOTE: the object will be allocated only.
     * @param klass The class of the object to allocate.
     * @return A new object.
     */
    static from(klass: _Il2CppClass) {
        return new _Il2CppObject(Api._objectNew(klass.handle));
    }

    /**
     * @return The unboxed value type.
     */
    unbox() {
        if (!this.class.isStruct) raise(`Cannot unbox a non value type object of class "${this.class.type.name}"`);
        return new _Il2CppValueType(Api._objectUnbox(this.handle), this.class);
    }
}
