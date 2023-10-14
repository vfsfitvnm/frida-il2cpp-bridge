namespace Il2Cpp {
    export class ValueType extends NativeStruct {
        constructor(handle: NativePointer, readonly type: Il2Cpp.Type) {
            super(handle);
        }

        /** Boxes the current value type in a object. */
        box(): Il2Cpp.Object {
            return new Il2Cpp.Object(Il2Cpp.api.valueTypeBox(this.type.class, this));
        }

        /** Gets the field with the given name. */
        field<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.Field<T> {
            return this.type.class.field<T>(name).withHolder(this);
        }

        /** Gets the method with the given name. */
        method<T extends Il2Cpp.Method.ReturnType>(name: string, parameterCount: number = -1): Il2Cpp.Method<T> {
            return this.type.class.method<T>(name, parameterCount).withHolder(this);
        }

        /** Gets the field with the given name. */
        tryField<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.Field<T> | undefined {
            return this.type.class.tryField<T>(name)?.withHolder(this);
        }

        /** Gets the field with the given name. */
        tryMethod<T extends Il2Cpp.Method.ReturnType>(name: string, parameterCount: number = -1): Il2Cpp.Method<T> | undefined {
            return this.type.class.tryMethod<T>(name, parameterCount)?.withHolder(this);
        }

        /** */
        toString(): string {
            const ToString = this.method<Il2Cpp.String>("ToString", 0);
            return this.isNull()
                ? "null"
                : // If ToString is defined within a value type class, we can
                // avoid a boxing operation.
                ToString.class.isValueType
                ? ToString.invoke().content ?? "null"
                : this.box().toString() ?? "null";
        }
    }
}
