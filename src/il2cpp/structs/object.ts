import { cache } from "decorator-cache-getter";

import { Accessor, filterAndMap } from "../../utils/accessor";
import { raise } from "../../utils/console";

import { Api } from "../api";
import { Invokable, Valuable } from "../interfaces";
import { NativeStruct } from "../native-struct";

import { _Il2CppClass } from "./class";
import { _Il2CppValueType } from "./value-type";


/**
 * Represents a `Il2CppObject`.
 */
export class _Il2CppObject extends NativeStruct {
    /** @internal */
    @cache
    static get headerSize(): number {
        return Api._objectGetHeaderSize();
    }

    /**
     * @return The same object as an instance of its parent.
     */
    @cache
    get base(): _Il2CppObject {
        if (this.class.parent == null) {
            raise(`Class "${this.class.type.name}" has no parent.`);
        }

        const object = new _Il2CppObject(this.handle);
        Reflect.defineProperty(object, "class", { get: (): _Il2CppClass => this.class.parent! });
        return object;
    }

    /**
     * @return Its class.
     */
    @cache
    get class(): _Il2CppClass {
        return new _Il2CppClass(Api._objectGetClass(this.handle));
    }

    /**
     * See {@link _Il2CppClass.fields} for an example.
     * @return Its fields.
     */
    @cache
    get fields(): Accessor<Valuable> {
        return this.class.fields[filterAndMap](
            field => field.isInstance,
            field => field.asHeld(this.handle.add(field.offset))
        );
    }

    /**
     * See {@link _Il2CppClass.methods} for an example.
     * @return Its methods.
     */
    @cache
    get methods(): Accessor<Invokable> {
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
    static from(klass: _Il2CppClass): _Il2CppObject {
        return new _Il2CppObject(Api._objectNew(klass.handle));
    }

    /**
     * @return The unboxed value type.
     */
    unbox(): _Il2CppValueType {
        if (!this.class.isStruct) raise(`Cannot unbox a non value type object of class "${this.class.type.name}"`);
        return new _Il2CppValueType(Api._objectUnbox(this.handle), this.class);
    }
}
