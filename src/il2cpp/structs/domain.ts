import { cache } from "decorator-cache-getter";

import { Accessor } from "utils/accessor";
import { raise } from "utils/logger";

import { Api } from "il2cpp/api";
import { NativeStruct } from "il2cpp/native-struct";
import { nonNullHandle } from "il2cpp/decorators";

import { _Il2CppAssembly } from "./assembly";

/**
 * Represents a `Il2CppDomain`.
 * ```typescript
 * assert(Il2Cpp.domain.name == "IL2CPP Root Domain");
 * ```
 */
@nonNullHandle
export class _Il2CppDomain extends NativeStruct {
    /**
     * @return Its name. Probably `IL2CPP Root Domain`.
     */
    @cache get name() {
        return Api._domainGetName(this.handle);
    }

    /**
     * We can iterate over the assemblies using a `for..of` loop,
     * or access a specific assembly using its name, extension omitted.
     * ```typescript
     * for (const assembly of Il2Cpp.domain.assemblies) {
     * }
     * const mscorlib = assemblies.mscorlib;
     * ```
     * @return Its assemblies.
     */
    @cache get assemblies() {
        const accessor = new Accessor<_Il2CppAssembly>();

        const sizePointer = Memory.alloc(Process.pointerSize);
        const startPointer = Api._domainGetAssemblies(NULL, sizePointer);

        if (startPointer.isNull()) {
            raise("First assembly pointer is NULL.");
        }

        const count = sizePointer.readInt();

        for (let i = 0; i < count; i++) {
            const assembly = new _Il2CppAssembly(startPointer.add(i * Process.pointerSize).readPointer());
            accessor[assembly.name!] = assembly;
        }
        return accessor;
    }

    /**
     * This is potentially asynchronous because the domain could
     * be initialized at any time, e.g. after `il2cpp_init` is
     * being called.\
     * The domain will already be attached to the caller thread.
     * You don't actually need to call this.
     * ```typescript
     * const domain = await Il2Cpp.Domain.reference;
     * const domain = Il2Cpp.domain;
     * ```
     * @return The current application domain.
     */
    @cache static get reference() {
        return (async () => {
            const domainPointer = await new Promise<NativePointer>(resolve => {
                const start = Api._domainGetAssemblies(NULL, Memory.alloc(Process.pointerSize));
                if (!start.isNull()) {
                    resolve(Api._domainGet());
                } else {
                    const interceptor = Interceptor.attach(Api._init, {
                        onLeave() {
                            setTimeout(() => interceptor.detach());
                            resolve(Api._domainGet());
                        }
                    });
                }
            });
            Api._threadAttach(domainPointer);
            return new _Il2CppDomain(domainPointer);
        })();
    }
}
