import Api from "./api";
import { lazy } from "../utils/decorators";
import Il2CppType from "./type";
import { raise } from "../utils/console";
import { allocRawValue, readRawValue, Valuable } from "./runtime";

/** @internal */
export default class Il2CppParameter {
    constructor(readonly handle: NativePointer) {
        if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
    }

    @lazy get name() {
        return Api._parameterGetName(this.handle)!;
    }

    @lazy get position() {
        return Api._parameterGetPosition(this.handle);
    }

    @lazy get type() {
        return new Il2CppType(Api._parameterGetType(this.handle));
    }

    asHeld(holder: InvocationArguments, startIndex: number) {
        const position = this.position;
        const type = this.type;
        return {
            valueHandle: holder[startIndex + position],
            get value() {
                return readRawValue(holder[startIndex + position], type);
            },
            set value(v) {
                holder[startIndex + position] = allocRawValue(v, type);
            }
        } as Valuable;
    }
}
