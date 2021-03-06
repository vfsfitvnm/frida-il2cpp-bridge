import { cache } from "decorator-cache-getter";

import { addLevenshtein, filterMap, overridePropertyValue } from "../../utils/record";
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
    get base(): Il2Cpp.Object {
        return overridePropertyValue(new Il2Cpp.Object(this), "class", this.class.parent!);
    }

    @cache
    get class(): Il2Cpp.Class {
        return new Il2Cpp.Class(Api._objectGetClass(this));
    }

    @cache
    get fields(): Readonly<Record<string, Il2Cpp.WithValue>> {
        return addLevenshtein(
            filterMap(
                this.class.fields,
                (field: Il2Cpp.Field) => !field.isStatic,
                (field: Il2Cpp.Field) => field.asHeld(this.handle.add(field.offset))
            )
        );
    }

    @cache
    get methods(): Readonly<Record<string, Il2Cpp.Invokable>> {
        return addLevenshtein(
            filterMap(
                this.class.methods,
                (method: Il2Cpp.Method) => !method.isStatic,
                (method: Il2Cpp.Method) => method.asHeld(this.handle)
            )
        );
    }

    static from(klass: Il2Cpp.Class): Il2Cpp.Object {
        return new Il2Cpp.Object(Api._objectNew(klass));
    }

    ref(pin: boolean): Il2Cpp.GCHandle {
        return new Il2Cpp.GCHandle(Api._gcHandleNew(this, pin));
    }

    unbox(): Il2Cpp.ValueType {
        if (!this.class.isValueType) {
            raise(`Cannot unbox a non value type object of class "${this.class.type.name}"`);
        }
        return new Il2Cpp.ValueType(Api._objectUnbox(this), this.class);
    }

    weakRef(trackResurrection: boolean): Il2Cpp.GCHandle {
        return new Il2Cpp.GCHandle(Api._gcHandleNewWeakRef(this, trackResurrection));
    }
}
