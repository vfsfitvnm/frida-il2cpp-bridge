import { cache } from "decorator-cache-getter";

import { Accessor } from "../../utils/accessor";
import { raise } from "../../utils/console";

import { Api } from "../api";
import { NativeStruct } from "../native-struct";
import { nonNullHandle } from "../decorators";

import { _Il2CppAssembly } from "./assembly";

/**
 * Represents a `Il2CppDomain`.
 */
@nonNullHandle
export class _Il2CppDomain extends NativeStruct {

    /**
     * Gets the name of the current application domain.
     */
    @cache
    get name(): string | null {
        return Api._domainGetName(this.handle);
    }

    /**
     * Gets the assemblies that have been loaded into the execution context of the current application domain.
     */
    @cache
    get assemblies(): Accessor<_Il2CppAssembly> {
        const accessor = new Accessor<_Il2CppAssembly>();

        const sizePointer = Memory.alloc(Process.pointerSize);
        const startPointer = Api._domainGetAssemblies(NULL, sizePointer);

        if (startPointer.isNull()) {
            raise("First assembly pointer is NULL.");
        }

        const count = sizePointer.readInt();

        for (let i = 0; i < count; i++) {
            const assembly = new _Il2CppAssembly(startPointer.add(i * Process.pointerSize).readPointer());
            accessor[assembly.name] = assembly;
        }

        return accessor;
    }

    /**
     * Gets the current application domain.
     */
    @cache
    static get reference(): _Il2CppDomain {
        const domainPointer = Api._domainGet();

        Api._threadAttach(domainPointer);

        return new _Il2CppDomain(domainPointer);

        // async function execute(): Promise<_Il2CppDomain> {
        //     const domainPointer = await domainPointerPromise;
        //
        //     Api._threadAttach(domainPointer);
        //     return new _Il2CppDomain(domainPointer);
        // }
        //
        // const domainPointerPromise = new Promise<NativePointer>(resolve => {
        //     if (Api._domainGetAssemblies(NULL, Memory.alloc(Process.pointerSize)).isNull()) {
        //         const interceptor = Interceptor.attach(Api._init, {
        //             onLeave() {
        //                 setTimeout(() => interceptor.detach());
        //                 resolve(Api._domainGet());
        //             }
        //         });
        //     } else {
        //         resolve(Api._domainGet());
        //     }
        // });
        //
        // return execute();
    }
}
