import { filterAndMap } from "../utils/accessor";
import { lazy } from "../utils/decorators";
import Il2CppClass from "./class";
import Il2CppObject from "./object";
import { raise } from "../utils/console";
import Api from "./api";

/** @internal */
export default class Il2CppValueType {
    constructor(readonly handle: NativePointer, readonly klass: Il2CppClass) {
        if (this.handle.isNull()) {
            raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
        }
    }

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
