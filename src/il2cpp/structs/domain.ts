import { cache } from "decorator-cache-getter";

import { Accessor } from "../../utils/accessor";

import { Api } from "../api";
import { NativeStructNotNull } from "../../utils/native-struct";
import { injectToIl2Cpp } from "../decorators";

@injectToIl2Cpp("Domain")
class Il2CppDomain extends NativeStructNotNull {
    @cache
    static get reference(): Il2Cpp.Domain {
        return new Il2Cpp.Domain(Api._domainGet());
    }

    @cache
    get name(): string | null {
        return Api._domainGetName(this.handle);
    }

    get assemblies(): Accessor<Il2Cpp.Assembly> {
        const accessor = new Accessor<Il2Cpp.Assembly>();

        const sizePointer = Memory.alloc(Process.pointerSize);
        const startPointer = Api._domainGetAssemblies(NULL, sizePointer);

        const count = sizePointer.readInt();

        for (let i = 0; i < count; i++) {
            const assembly = new Il2Cpp.Assembly(startPointer.add(i * Process.pointerSize).readPointer());
            accessor[assembly.name] = assembly;
        }

        return accessor;
    }
}
