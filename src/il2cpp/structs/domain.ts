import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

import { NativeStruct } from "../../utils/native-struct";
import { addLevenshtein } from "../../utils/record";

@injectToIl2Cpp("Domain")
class Il2CppDomain extends NativeStruct {
    @cache
    static get reference(): Il2Cpp.Domain {
        return new Il2Cpp.Domain(Api._domainGet());
    }

    @cache
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

    @cache
    get name(): string {
        return Api._domainGetName(this);
    }
}
