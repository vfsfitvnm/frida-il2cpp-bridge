import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

import { NonNullNativeStruct } from "../../utils/native-struct";

@injectToIl2Cpp("Parameter")
class Il2CppParameter extends NonNullNativeStruct {
    @cache
    get name(): string {
        return Api._parameterGetName(this)!;
    }

    @cache
    get position(): number {
        return Api._parameterGetPosition(this);
    }

    @cache
    get type(): Il2Cpp.Type {
        return new Il2Cpp.Type(Api._parameterGetType(this));
    }
}
