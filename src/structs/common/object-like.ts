namespace Il2Cpp {
    export abstract class ObjectLike extends NativeStruct {
        abstract get class(): Il2Cpp.Class;
        abstract get type(): Il2Cpp.Type;

        /** Gets the field with the given name. */
        field<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.HeldField<T> {
            return this.type.class.field<T>(name).withHolder(this);
        }

        /** Gets the method with the given name. */
        method<T extends Il2Cpp.Method.ReturnType>(name: string, parameterCount: number = -1): Il2Cpp.HeldMethod<T> {
            return this.type.class.method<T>(name, parameterCount).withHolder(this);
        }

        methodWithSignature<T extends Il2Cpp.Method.ReturnType>(name: string, ...paramTypes: Il2Cpp.Type[]): Il2Cpp.HeldMethod<T> {
            return this.type.class.methodWithSignature<T>(name, ...paramTypes).withHolder(this);
        }

        /** Gets the field with the given name. */
        tryField<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.HeldField<T> | undefined {
            return this.type.class.tryField<T>(name)?.withHolder(this);
        }

        /** Gets the field with the given name. */
        tryMethod<T extends Il2Cpp.Method.ReturnType>(name: string, parameterCount: number = -1): Il2Cpp.HeldMethod<T> | undefined {
            return this.type.class.tryMethod<T>(name, parameterCount)?.withHolder(this);
        }

        tryMethodWithSignature<T extends Il2Cpp.Method.ReturnType>(name: string, ...paramTypes: Il2Cpp.Type[]): Il2Cpp.HeldMethod<T> | undefined {
            return this.type.class.methodWithSignature<T>(name, ...paramTypes).withHolder(this);
        }

        @lazy
        get m(): Il2Cpp.DynamicMethods {
            return Il2Cpp.DynamicMethodsLookup.from(this, false);
        }
    }
}
