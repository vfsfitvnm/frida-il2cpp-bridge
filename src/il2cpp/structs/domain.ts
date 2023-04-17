namespace Il2Cpp {
    /** Represents a `Il2CppDomain`. */
    export class Domain {
        protected constructor() {}

        /** Gets the assemblies that have been loaded into the execution context of the application domain. */
        @lazy
        static get assemblies(): Il2Cpp.Assembly[] {
            let handles = readNativeList(_ => Il2Cpp.Api.domainGetAssemblies(this, _));

            if (handles.length == 0) {
                const assemblyObjects = this.object.method<Il2Cpp.Array<Il2Cpp.Object>>("GetAssemblies").overload().invoke();
                handles = globalThis.Array.from(assemblyObjects).map(_ => _.field<NativePointer>("_mono_assembly").value);
            }

            return handles.map(_ => new Il2Cpp.Assembly(_));
        }

        /** Gets the application domain handle. */
        @lazy
        static get handle(): NativePointer {
            return Il2Cpp.Api.domainGet();
        }

        /** Gets the encompassing object of the application domain. */
        @lazy
        static get object(): Il2Cpp.Object {
            return new Il2Cpp.Object(Il2Cpp.Api.domainGetObject());
        }

        /** Opens and loads the assembly with the given name. */
        static assembly(name: string): Il2Cpp.Assembly {
            // prettier-ignore
            return this.tryAssembly(name) ?? keyNotFound(name, "Domain", this.assemblies.map(_ => _.name));
        }

        /** Attached a new thread to the application domain. */
        static attach(): Il2Cpp.Thread {
            return new Il2Cpp.Thread(Il2Cpp.Api.threadAttach(this));
        }

        /** Opens and loads the assembly with the given name. */
        static tryAssembly(name: string): Il2Cpp.Assembly | null {
            const handle = Il2Cpp.Api.domainAssemblyOpen(this, Memory.allocUtf8String(name));
            return handle.isNull() ? null : new Il2Cpp.Assembly(handle);
        }
    }
}
