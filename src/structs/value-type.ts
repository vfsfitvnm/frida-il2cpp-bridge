namespace Il2Cpp {
    export class ValueType extends NativeStruct {
        constructor(handle: NativePointer, readonly type: Il2Cpp.Type) {
            super(handle);
        }

        /** Boxes the current value type in a object. */
        box(): Il2Cpp.Object {
            return new Il2Cpp.Object(Il2Cpp.exports.valueTypeBox(this.type.class, this));
        }

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
