import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { checkNull, injectToIl2Cpp } from "../decorators";

import { NativeStruct } from "../../utils/native-struct";
import { addLevenshtein, filterMap, overridePropertyValue } from "../../utils/utils";

@injectToIl2Cpp("Object")
class Il2CppObject extends NativeStruct {
    @cache
    static get headerSize(): number {
        return Api._objectGetHeaderSize();
    }

    static from(klass: Il2Cpp.Class): Il2Cpp.Object {
        return new Il2Cpp.Object(Api._objectNew(klass));
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
    get fields(): Readonly<Record<string, Il2Cpp.Field>> {
        return addLevenshtein(
            filterMap(
                this.class.fields,
                (field: Il2Cpp.Field) => !field.isStatic,
                (field: Il2Cpp.Field) => field.withHolder(this)
            )
        );
    }

    @cache
    get methods(): Readonly<Record<string, Il2Cpp.Method>> {
        return addLevenshtein(
            filterMap(
                this.class.methods,
                (method: Il2Cpp.Method) => !method.isStatic,
                (method: Il2Cpp.Method) => method.withHolder(this)
            )
        );
    }

    ref(pin: boolean): Il2Cpp.GCHandle {
        return new Il2Cpp.GCHandle(Api._gcHandleNew(this, +pin));
    }

    unbox(): NativePointer {
        return Api._objectUnbox(this);
    }

    weakRef(trackResurrection: boolean): Il2Cpp.GCHandle {
        return new Il2Cpp.GCHandle(Api._gcHandleNewWeakRef(this, +trackResurrection));
    }

    @checkNull
    override toString(): string | null {
        let object: Il2Cpp.Object = this;
        while (!("ToString" in object.methods)) {
            object = object.base;
        }
        return object.methods.ToString.invoke<Il2Cpp.String>().content;

        // if ("ToString" in this.methods) {
        //     return this.methods.ToString.invoke<Il2Cpp.String>().content;
        // } else {
        // const UnityEngineJSONSerializeModule = Il2Cpp.Domain.reference.assemblies["UnityEngine.JSONSerializeModule"];
        // return UnityEngineJSONSerializeModule.image.classes["UnityEngine.JsonUtility"].methods.ToJson_.invoke<Il2Cpp.String>(this, true)
        //     .content;
        // return `{ ${mapToArray(this.fields, (field: Il2Cpp.Field) => `${field.name} = ${field.value}`).join(", ")} }`;
        // }
    }
}
