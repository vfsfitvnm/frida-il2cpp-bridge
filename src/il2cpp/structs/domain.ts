import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

import { getOrNull, NativeStruct } from "../../utils/native-struct";
import { addLevenshtein } from "../../utils/utils";
import { warn } from "../../utils/console";

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

        if (count == 0) {
            warn("The domain contains 0 assemblies, let's follow plan B.");
            const AppDomain = Il2Cpp.Image.corlib.classes["System.AppDomain"].methods.get_CurrentDomain.invoke<Il2Cpp.Object>();

            for (const assemblyObject of AppDomain.methods.GetAssemblies_.invoke<Il2Cpp.Array<Il2Cpp.Object>>()) {
                const assemblyName = assemblyObject.base.base.methods.GetSimpleName.invoke<Il2Cpp.String>().content;

                if (assemblyName != null) {
                    const assembly = Il2Cpp.Domain.reference.open(assemblyName);
                    if (assembly != null) {
                        record[assembly.name] = assembly;
                    }
                }
            }
        }

        return addLevenshtein(record);
    }

    @cache
    get name(): string {
        return Api._domainGetName(this).readUtf8String()!;
    }

    open(assemblyName: string): Il2Cpp.Assembly | null {
        return getOrNull(Api._domainAssemblyOpen(this, Memory.allocUtf8String(assemblyName)), Il2Cpp.Assembly);
    }
}
