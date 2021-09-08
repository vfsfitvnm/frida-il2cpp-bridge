import { cache } from "decorator-cache-getter";

import { addLevenshtein, getOrNull, makeIterable } from "../../utils/utils";

/** Represents a `Il2CppDomain`. */
class Il2CppDomain {
    protected constructor() {}

    /** Gets the assemblies that have been loaded into the execution context of the application domain. */
    @cache
    static get assemblies(): IterableRecord<Il2Cpp.Assembly> {
        const record: Record<string, Il2Cpp.Assembly> = {};

        const sizePointer = Memory.alloc(Process.pointerSize);
        const startPointer = Il2Cpp.Api._domainGetAssemblies(this, sizePointer);

        const count = sizePointer.readInt();

        for (let i = 0; i < count; i++) {
            const assembly = new Il2Cpp.Assembly(startPointer.add(i * Process.pointerSize).readPointer());
            record[assembly.name] = assembly;
        }

        if (count == 0) {
            const AppDomain = Il2Cpp.Image.corlib.classes["System.AppDomain"].methods.get_CurrentDomain.invoke<Il2Cpp.Object>();

            for (const assemblyObject of AppDomain.methods.GetAssemblies_.invoke<Il2Cpp.Array<Il2Cpp.Object>>()) {
                const assemblyName = assemblyObject.base.base.methods.GetSimpleName.invoke<Il2Cpp.String>().content;

                if (assemblyName != null) {
                    const assembly = Il2Cpp.Domain.open(assemblyName);

                    if (assembly != null) {
                        record[assembly.name] = assembly;
                    }
                }
            }
        }

        return makeIterable(addLevenshtein(record));
    }

    /** Gets the application domain handle. */
    @cache
    static get handle(): NativePointer {
        return Il2Cpp.Api._domainGet();
    }

    /** Gets the name of the application domain. */
    @cache
    // @ts-ignore
    static get name(): string {
        return Il2Cpp.Api._domainGetName(this).readUtf8String()!;
    }

    /** Attached a new thread to the application domain. */
    static attach(): Il2Cpp.Thread {
        return new Il2Cpp.Thread(Il2Cpp.Api._threadAttach(this));
    }

    /** Opens and loads the assembly with the given name. */
    static open(assemblyName: string): Il2Cpp.Assembly | null {
        return getOrNull(Il2Cpp.Api._domainAssemblyOpen(this, Memory.allocUtf8String(assemblyName)), Il2Cpp.Assembly);
    }
}

Il2Cpp.Domain = Il2CppDomain;

declare global {
    namespace Il2Cpp {
        class Domain extends Il2CppDomain {}
    }
}
