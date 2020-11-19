import { filterAndMap } from "../utils/accessor";
import { lazy } from "../utils/decorators";
import Il2CppClass from "./class";
import Il2CppObject from "./object";
import Api from "./api";

/** @internal */
export default class Il2CppValueType {
    constructor(readonly handle: NativePointer, readonly klass: Il2CppClass) {}

    get class() {
        return this.klass;
    }

    @lazy get fields() {
        return this.class!.fields[filterAndMap](
            field => field.isInstance,
            field => field.asHeld(this.handle.add(field.offset).sub(Il2CppObject.headerSize))
        );
    }

    box() {
        return new Il2CppObject(Api._valueBox(this.klass.handle, this.handle));
    }
}
