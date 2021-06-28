import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { NativeStructNotNull } from "../../utils/native-struct";
import { allocRawValue, readRawValue } from "../utils";
import { injectToIl2Cpp } from "../decorators";

@injectToIl2Cpp("Parameter")
class Il2CppParameter extends NativeStructNotNull {
    @cache
    get name(): string {
        return Api._parameterGetName(this.handle)!;
    }

    @cache
    get position(): number {
        return Api._parameterGetPosition(this.handle);
    }

    @cache
    get type(): Il2Cpp.Type {
        return new Il2Cpp.Type(Api._parameterGetType(this.handle));
    }

    asHeld(holder: InvocationArguments, startIndex: number): Il2Cpp.WithValue {
        const position = this.position;
        const type = this.type;
        return {
            valueHandle: holder[startIndex + position],
            get value(): Il2Cpp.AllowedType {
                return readRawValue(holder[startIndex + position], type);
            },
            set value(v: Il2Cpp.AllowedType) {
                holder[startIndex + position] = allocRawValue(v, type);
            }
        } as Il2Cpp.WithValue;
    }
}
