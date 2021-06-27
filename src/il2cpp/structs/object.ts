import { cache } from "decorator-cache-getter";

import { Accessor, filterAndMap } from "../../utils/accessor";
import { NativeStruct } from "../../utils/native-struct";
import { raise } from "../../utils/console";

import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

@injectToIl2Cpp("Object")
class Il2CppObject extends NativeStruct {
    @cache
    static get headerSize(): number {
        return Api._objectGetHeaderSize();
    }

    @cache
    get base() {
        if (this.class.parent == null) {
            raise(`Class "${this.class.type.name}" has no parent.`);
        }

        const object = new Il2Cpp.Object(this.handle);
        Reflect.defineProperty(object, "class", { get: (): Il2Cpp.Class => this.class.parent! });
        return object;
    }

    @cache
    get class(): Il2Cpp.Class {
        return new Il2Cpp.Class(Api._objectGetClass(this.handle));
    }

    @cache
    get fields(): Accessor<Il2Cpp.Valuable> {
        return this.class.fields[filterAndMap](
            field => !field.isStatic,
            field => field.asHeld(this.handle.add(field.offset))
        );
    }

    @cache
    get methods(): Accessor<Il2Cpp.Invokable> {
        return this.class.methods[filterAndMap](
            method => !method.isStatic,
            method => method.asHeld(this.handle)
        );
    }

    static from(klass: Il2Cpp.Class): Il2Cpp.Object {
        return new Il2Cpp.Object(Api._objectNew(klass.handle));
    }

    ref(pin: boolean): Il2Cpp.GCHandle {
        return new Il2Cpp.GCHandle(Api._gcHandleNew(this.handle, pin));
    }

    unbox(): Il2Cpp.ValueType {
        if (!this.class.isValueType) {
            raise(`Cannot unbox a non value type object of class "${this.class.type.name}"`);
        }
        return new Il2Cpp.ValueType(Api._objectUnbox(this.handle), this.class);
    }

    weakRef(trackResurrection: boolean): Il2Cpp.GCHandle {
        return new Il2Cpp.GCHandle(Api._gcHandleNewWeakRef(this.handle, trackResurrection));
    }
}
