import { cache } from "decorator-cache-getter";
import { memoize } from "../../utils/utils";
import { levenshtein } from "../decorators";

/** Represents a `Il2CppDomain`. */
class Il2CppDomain {
    protected constructor() {}

    /** Gets the assemblies that have been loaded into the execution context of the application domain. */
    @cache
    static get assemblies(): Il2Cpp.Assembly[] {
        const sizePointer = Memory.alloc(Process.pointerSize);
        const startPointer = Il2Cpp.Api._domainGetAssemblies(this, sizePointer);

        const count = sizePointer.readInt();
        const array: Il2Cpp.Assembly[] = new Array(count);

        for (let i = 0; i < count; i++) {
            array[i] = new Il2Cpp.Assembly(startPointer.add(i * Process.pointerSize).readPointer());
        }

        if (count == 0) {
            for (const assemblyObject of this.object.method("GetAssemblies", 0).invoke<Il2Cpp.Array<Il2Cpp.Object>>()) {
                const assemblyName = assemblyObject.base.base.method("GetSimpleName").invoke<Il2Cpp.String>().content;

                if (assemblyName != null) {
                    array.push(this.assembly(assemblyName));
                }
            }
        }

        return array;
    }

    /** Gets the application domain handle. */
    @cache
    static get handle(): NativePointer {
        return Il2Cpp.Api._domainGet();
    }

    /** Gets the encompassing object of the application domain. */
    @cache
    static get object(): Il2Cpp.Object {
        return Il2Cpp.Image.corlib.class("System.AppDomain").method("get_CurrentDomain").invoke<Il2Cpp.Object>();
    }

    /** Opens and loads the assembly with the given name. */
    @levenshtein("assemblies")
    static assembly(name: string): Il2Cpp.Assembly {
        return this.tryAssembly(name)!;
    }

    /** Attached a new thread to the application domain. */
    static attach(): Il2Cpp.Thread {
        return new Il2Cpp.Thread(Il2Cpp.Api._threadAttach(this));
    }

    /** Opens and loads the assembly with the given name. */
    @memoize
    static tryAssembly(name: string): Il2Cpp.Assembly | null {
        const handle = Il2Cpp.Api._domainAssemblyOpen(this, Memory.allocUtf8String(name));
        return handle.isNull() ? null : new Il2Cpp.Assembly(handle);
    }
}

Il2Cpp.Domain = Il2CppDomain;

declare global {
    namespace Il2Cpp {
        class Domain extends Il2CppDomain {}
    }
}
