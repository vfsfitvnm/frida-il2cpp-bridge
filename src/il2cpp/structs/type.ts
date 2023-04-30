namespace Il2Cpp {
    export class Type extends NonNullNativeStruct {
        /** Gets the class of this type. */
        @lazy
        get class(): Il2Cpp.Class {
            return new Il2Cpp.Class(Il2Cpp.api.classFromType(this));
        }

        /** */
        @lazy
        get fridaAlias(): NativeCallbackArgumentType {
            if (this.isByReference) {
                return "pointer";
            }

            switch (this.typeEnum) {
                case Il2Cpp.Type.Enum.Void:
                    return "void";
                case Il2Cpp.Type.Enum.Boolean:
                    return "bool";
                case Il2Cpp.Type.Enum.Char:
                    return "uchar";
                case Il2Cpp.Type.Enum.I1:
                    return "int8";
                case Il2Cpp.Type.Enum.U1:
                    return "uint8";
                case Il2Cpp.Type.Enum.I2:
                    return "int16";
                case Il2Cpp.Type.Enum.U2:
                    return "uint16";
                case Il2Cpp.Type.Enum.I4:
                    return "int32";
                case Il2Cpp.Type.Enum.U4:
                    return "uint32";
                case Il2Cpp.Type.Enum.I8:
                    return "int64";
                case Il2Cpp.Type.Enum.U8:
                    return "uint64";
                case Il2Cpp.Type.Enum.R4:
                    return "float";
                case Il2Cpp.Type.Enum.R8:
                    return "double";
                case Il2Cpp.Type.Enum.ValueType:
                    return getValueTypeFields(this);
                case Il2Cpp.Type.Enum.NativeInteger:
                case Il2Cpp.Type.Enum.UnsignedNativeInteger:
                case Il2Cpp.Type.Enum.Pointer:
                case Il2Cpp.Type.Enum.String:
                case Il2Cpp.Type.Enum.SingleDimensionalZeroLowerBoundArray:
                case Il2Cpp.Type.Enum.Array:
                    return "pointer";
                case Il2Cpp.Type.Enum.Class:
                case Il2Cpp.Type.Enum.Object:
                case Il2Cpp.Type.Enum.GenericInstance:
                    return this.class.isValueType ? getValueTypeFields(this) : "pointer";
                default:
                    return "pointer";
            }
        }

        /** Determines whether this type is passed by reference. */
        @lazy
        get isByReference(): boolean {
            return !!Il2Cpp.api.typeIsByReference(this);
        }

        /** Determines whether this type is primitive. */
        @lazy
        get isPrimitive(): boolean {
            return !!Il2Cpp.api.typeIsPrimitive(this);
        }

        /** Gets the name of this type. */
        @lazy
        get name(): string {
            const handle = Il2Cpp.api.typeGetName(this);

            try {
                return handle.readUtf8String()!;
            } finally {
                Il2Cpp.free(handle);
            }
        }

        /** Gets the encompassing object of the current type. */
        @lazy
        get object(): Il2Cpp.Object {
            return new Il2Cpp.Object(Il2Cpp.api.typeGetObject(this));
        }

        /** Gets the type enum of the current type. */
        @lazy
        get typeEnum(): Il2Cpp.Type.Enum {
            return Il2Cpp.api.typeGetTypeEnum(this);
        }

        /** */
        toString(): string {
            return this.name;
        }
    }

    function getValueTypeFields(type: Il2Cpp.Type): NativeCallbackArgumentType {
        const instanceFields = type.class.fields.filter(_ => !_.isStatic);
        return instanceFields.length == 0 ? ["char"] : instanceFields.map(_ => _.type.fridaAlias);
    }
}
