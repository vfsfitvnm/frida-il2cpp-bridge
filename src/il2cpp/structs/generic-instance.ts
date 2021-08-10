import { cache } from "decorator-cache-getter";

import { NonNullNativeStruct } from "../../utils/native-struct";
import { addLevenshtein } from "../../utils/utils";

/** Represents a `Il2CppGenericInst`. */
class Il2CppGenericInstance extends NonNullNativeStruct {
    /** */
    @cache
    get typesCount(): number {
        return Il2Cpp.Api._genericInstanceGetTypeCount(this);
    }

    /** */
    @cache
    get types(): Readonly<Record<string, Il2Cpp.Type>> {
        const record: Record<string, Il2Cpp.Type> = {};

        const startPointer = Il2Cpp.Api._genericInstanceGetTypes(this);

        for (let i = 0; i < this.typesCount; i++) {
            const type = new Il2Cpp.Type(startPointer.add(i * Process.pointerSize).readPointer());
            record[type.name] = type;
        }

        return addLevenshtein(record);
    }
}

Il2Cpp.GenericInstance = Il2CppGenericInstance;

declare global {
    namespace Il2Cpp {
        class GenericInstance extends Il2CppGenericInstance {}
    }
}
