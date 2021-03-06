import { cache } from "decorator-cache-getter";

import { addLevenshtein } from "../../utils/record";

import { Api } from "../api";
import { NonNullNativeStruct } from "../../utils/native-struct";
import { injectToIl2Cpp } from "../decorators";

@injectToIl2Cpp("Domain")
class Il2CppDomain extends NonNullNativeStruct {
    @cache
    static get reference(): Il2Cpp.Domain {
        return new Il2Cpp.Domain(Api._domainGet());
    }

    @cache
    get name(): string | null {
        return Api._domainGetName(this);
    }

    get assemblies(): Readonly<Record<string, Il2Cpp.Assembly>> {
        const record: Record<string, Il2Cpp.Assembly> = {};

        const sizePointer = Memory.alloc(Process.pointerSize);
        const startPointer = Api._domainGetAssemblies(this, sizePointer);

        const count = sizePointer.readInt();

        for (let i = 0; i < count; i++) {
            const assembly = new Il2Cpp.Assembly(startPointer.add(i * Process.pointerSize).readPointer());
            record[assembly.name] = assembly;
        }

        return addLevenshtein(record);
    }
}
