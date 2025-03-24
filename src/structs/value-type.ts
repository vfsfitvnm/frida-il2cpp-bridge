namespace Il2Cpp {
    export class ValueType extends Il2Cpp.InstanceType {
        constructor(handle: NativePointer, /** @internal */ readonly type: Il2Cpp.Type) {
            super(handle);
        }

        /** Gets the class of this value type. */
        get class() {
            return this.type.class;
        }

        /** Boxes the current value type in a object. */
        box(): Il2Cpp.Object {
            return new Il2Cpp.Object(Il2Cpp.exports.valueTypeBox(this.class, this));
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
