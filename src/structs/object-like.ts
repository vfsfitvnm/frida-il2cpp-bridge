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
        get m(): DynamicMethods {
            return new ObjectMethods(this) as unknown as DynamicMethods;
        }
    }

    type DynamicMethods = {
        [K in Exclude<string, ["constructor" | "#invokeMethod"]>]: (...parameters: (Il2Cpp.Parameter.TypeValue | Il2Cpp.Parameter.Type)[]) => any;
    };

    class ObjectMethods {
        constructor(public readonly object: Il2Cpp.ObjectLike) {
            this.object.class.methods
                .filter(m => !m.isStatic)
                .forEach(m => {
                    globalThis.Object.defineProperty(this, m.name, {
                        value: this.#invokeMethod.bind(this, m.name),
                        enumerable: true,
                        configurable: true
                    });
                });
        }

        #invokeMethod<T extends Il2Cpp.Method.ReturnType>(name: string, ...parameters: (Il2Cpp.Parameter.TypeValue | Il2Cpp.Parameter.Type)[]): T {
            const paramTypes = parameters.map(p => (Il2Cpp.Parameter.isTypeValue(p) ? p.type : Il2Cpp.Type.fromValue(p)));
            const paramValues = parameters.map(p => (Il2Cpp.Parameter.isTypeValue(p) ? p.value : p));

            return this.object.methodWithSignature<T>(name, ...paramTypes).invoke(...paramValues);
        }
    }
}
