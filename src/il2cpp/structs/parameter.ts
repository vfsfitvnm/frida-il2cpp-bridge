import { cache } from "decorator-cache-getter";
import { NonNullNativeStruct } from "../../utils/native-struct";
import { readGString } from "../utils";

/** Represents a `ParameterInfo`. */
class Il2CppParameter extends NonNullNativeStruct {
    /** Gets the name of this parameter. */
    @cache
    get name(): string {
        return Il2Cpp.Api._parameterGetName(this).readUtf8String()!;
    }

    /** Gets the position of this parameter. */
    @cache
    get position(): number {
        return Il2Cpp.Api._parameterGetPosition(this);
    }

    /** Gets the type of this parameter. */
    @cache
    get type(): Il2Cpp.Type {
        return new Il2Cpp.Type(Il2Cpp.Api._parameterGetType(this));
    }

    override toString(): string {
        return readGString(Il2Cpp.Api._toString(this, Il2Cpp.Api._parameterToString))!;
    }
}

Il2Cpp.Parameter = Il2CppParameter;

declare global {
    namespace Il2Cpp {
        class Parameter extends Il2CppParameter {}
        namespace Parameter {
            type Type = Il2Cpp.Field.Type | Il2Cpp.Reference;
        }
    }
}
