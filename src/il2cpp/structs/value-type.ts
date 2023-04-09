namespace Il2Cpp {
    export class ValueType extends NativeStruct {
        constructor(handle: NativePointer, readonly type: Il2Cpp.Type) {
            super(handle);
        }

        /** Boxes the current value type in a object. */
        box(): Il2Cpp.Object {
            return new Il2Cpp.Object(Il2Cpp.Api._valueBox(this.type.class, this));
        }

        /** Gets the field with the given name. */
        field<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.Field<T> {
            return this.type.class.field<T>(name).withHolder(this);
        }

        /** */
        toString(): string {
            return this.isNull() ? "null" : this.box().toString();
        }
    }
}
