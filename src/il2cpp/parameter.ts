import Api from "./api";
import { lazy } from "../utils/decorators";
import Il2CppType from "./type";
import { raise } from "../utils/console";
import { allocRawValue, AllowedType, readRawValue, Valuable } from "./runtime";

/** @internal */
export default class Il2CppParameter implements Valuable {
    readonly valueHandle = NULL;

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

    get value() {
        raise(`Cannot access value of parameter "${this.name}" without an invocation context.`);
        return;
    }

    set value(v: AllowedType) {
        raise(`Cannot access value of parameter "${this.name}" without an invocation context.`);
    }

    asHeld(holder: InvocationArguments, startIndex: number) {
        const parameter: Il2CppParameter = { ...this };
        Reflect.set(parameter, "valueHandle", holder[startIndex + this.position]);
        Reflect.defineProperty(parameter, "value", {
            get: () => readRawValue(holder[startIndex + this.position], this.type!),
            set: (v: AllowedType) => (holder[startIndex + this.position] = allocRawValue(v, this.type!))
        });
        return parameter;
    }
}
