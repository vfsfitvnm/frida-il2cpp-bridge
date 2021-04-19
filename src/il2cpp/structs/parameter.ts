import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { nonNullHandle } from "../decorators";
import { Valuable } from "../interfaces";
import { NativeStruct } from "../native-struct";
import { allocRawValue, readRawValue } from "../utils";

import { _Il2CppType } from "./type";

/**
 * Represents a `ParameterInfo`.
 */
@nonNullHandle
export class _Il2CppParameter extends NativeStruct {
    /**
     * @return Its name.
     */
    @cache get name() {
        return Api._parameterGetName(this.handle)!;
    }

    /**
     * @return Its position.
     */
    @cache get position() {
        return Api._parameterGetPosition(this.handle);
    }

    /**
     *  @return Its type.
     */
    @cache get type() {
        return new _Il2CppType(Api._parameterGetType(this.handle));
    }

    /** @internal */
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
