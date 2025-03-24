namespace Il2Cpp {
    export abstract class InstanceType extends NativeStruct {
        abstract get class(): Il2Cpp.Class;

        /** Gets the non-static field with the given name of the current class hierarchy. */
        field<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.BoundField<T> {
            return this.tryField(name) ?? raise(`couldn't find non-static field ${name} in hierarchy of class ${this.class.type.name}`);
        }

        /** Gets the non-static method with the given name (and optionally parameter count) of the current class hierarchy. */
        method<T extends Il2Cpp.Method.ReturnType>(name: string, parameterCount: number = -1): Il2Cpp.BoundMethod<T> {
            return this.tryMethod<T>(name, parameterCount) ?? raise(`couldn't find non-static method ${name} in hierarchy of class ${this.class.type.name}`);
        }

        /** Gets the non-static field with the given name of the current class hierarchy, if it exists. */
        tryField<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.BoundField<T> | undefined {
            const field = this.class.tryField<T>(name);

            if (field?.isStatic) {
                // classes cannot have static and non-static fields with the
                // same name, hence we can immediately check the parent
                for (const klass of this.class.hierarchy({ includeCurrent: false })) {
                    for (const field of klass.fields) {
                        if (field.name == name && !field.isStatic) {
                            return field.bind(this) as Il2Cpp.Field<T>;
                        }
                    }
                }
                return undefined;
            }

            return field?.bind(this);
        }

        /** Gets the non-static method with the given name (and optionally parameter count) of the current class hierarchy, if it exists. */
        tryMethod<T extends Il2Cpp.Method.ReturnType>(name: string, parameterCount: number = -1): Il2Cpp.BoundMethod<T> | undefined {
            const method = this.class.tryMethod<T>(name, parameterCount);

            if (method?.isStatic) {
                for (const klass of this.class.hierarchy()) {
                    for (const method of klass.methods) {
                        if (method.name == name && !method.isStatic && (parameterCount < 0 || method.parameterCount == parameterCount)) {
                            return method.bind(this) as Il2Cpp.Method<T>;
                        }
                    }
                }
                return undefined;
            }

            return method?.bind(this);
        }
    }
}
