import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

import { NonNullNativeStruct } from "../../utils/native-struct";
import { addLevenshtein } from "../../utils/utils";

@injectToIl2Cpp("GenericInstance")
class Il2CppGenericInstance extends NonNullNativeStruct {
    @cache
    get typesCount(): number {
        return Api._genericInstanceGetTypeCount(this);
    }

    @cache
    get types(): Readonly<Record<string, Il2Cpp.Type>> {
        const record: Record<string, Il2Cpp.Type> = {};

        const startPointer = Api._genericInstanceGetTypes(this);

        for (let i = 0; i < this.typesCount; i++) {
            const type = new Il2Cpp.Type(startPointer.add(i * Process.pointerSize).readPointer());
            record[type.name] = type;
        }

        return addLevenshtein(record);
    }
}
