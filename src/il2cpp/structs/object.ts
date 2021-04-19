import { cache } from "decorator-cache-getter";

import { filterAndMap } from "../../utils/accessor";
import { raise } from "../../utils/console";

import { Api } from "../api";
import { NativeStruct } from "../native-struct";

import { _Il2CppClass } from "./class";
import { _Il2CppValueType } from "./value-type";

/**
 * Represents a `Il2CppObject`.
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
