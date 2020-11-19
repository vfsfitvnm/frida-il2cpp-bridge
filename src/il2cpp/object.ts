import Il2CppClass from "./class";
import Api from "./api";
import { filterAndMap } from "../utils/accessor";
import { lazy } from "../utils/decorators";
import { raise } from "../utils/console";
import Il2CppValueType from "./value-type";

/** @internal */
export default class Il2CppObject {
    constructor(readonly handle: NativePointer) {}

    @lazy
    static get headerSize() {
        return Api._objectGetHeaderSize();
    }

    @lazy get base() {
        if (this.class.parent == null) {
            raise(`Class "${this.class.type.name}" has no parent.`);
        }
        const object = new Il2CppObject(this.handle);
        Reflect.defineProperty(object, "class", { get: () => this.class.parent! });
        return object;
    }

    @lazy get class() {
        return new Il2CppClass(Api._objectGetClass(this.handle));
    }

    @lazy get fields() {
        return this.class!.fields[filterAndMap](
            field => field.isInstance,
            field => field.asHeld(this.handle.add(field.offset))
        );
    }

    @lazy get methods() {
        return this.class!.methods[filterAndMap](
            method => method.isInstance,
            method => method.asHeld(this.handle)
        );
    }

    static from(klass: Il2CppClass) {
        return new Il2CppObject(Api._objectNew(klass.handle));
    }

    unbox() {
        if (!this.class.isStruct) raise(`Cannot unbox a non value type object of class "${this.class.type.name}"`);
        return new Il2CppValueType(Api._objectUnbox(this.handle), this.class);
    }
}
