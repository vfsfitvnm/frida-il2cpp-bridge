import { cache } from "decorator-cache-getter";

import { shouldBeInstance } from "../decorators";
import { read, write } from "../utils";

import { warn } from "../../utils/console";
import { NonNullNativeStruct } from "../../utils/native-struct";
import { overridePropertyValue } from "../../utils/utils";

/** Represents a `FieldInfo`. */
class Il2CppField extends NonNullNativeStruct {
    /** Gets the class in which this field is defined. */
    @cache
    get class(): Il2Cpp.Class {
        return new Il2Cpp.Class(Il2Cpp.Api._fieldGetClass(this));
    }

    /** Gets the flags of the current field. */
    @cache
    get flags(): number {
        return Il2Cpp.Api._fieldGetFlags(this);
    }

    /** Determines whether this field value is written at compile time. */
    @cache
    get isLiteral(): boolean {
        return !!Il2Cpp.Api._fieldIsLiteral(this);
    }

    /** Determines whether this field is static. */
    @cache
    get isStatic(): boolean {
        return !Il2Cpp.Api._fieldIsInstance(this);
    }

    /** Determines whether this field is thread static. */
    @cache
    get isThreadStatic(): boolean {
        return this.offset == -1;
    }

    /** Gets the name of this field. */
    @cache
    get name(): string {
        return Il2Cpp.Api._fieldGetName(this).readUtf8String()!;
    }

    /** Gets the offset of this field, calculated as the difference with its owner virtual address. */
    @cache
    get offset(): number {
        return Il2Cpp.Api._fieldGetOffset(this);
    }

    /** Gets the type of this field. */
    @cache
    get type(): Il2Cpp.Type {
        return new Il2Cpp.Type(Il2Cpp.Api._fieldGetType(this));
    }

    /** Gets the value of this field. */
    get value(): Il2Cpp.Field.Type {
        return read(this.valueHandle, this.type);
    }

    /** @internal */
    @shouldBeInstance(false)
    get valueHandle(): NativePointer {
        if (this.isThreadStatic || this.isLiteral) {
            let valueHandle = Memory.alloc(Process.pointerSize);
            Il2Cpp.Api._fieldGetStaticValue(this.handle, valueHandle);
            return valueHandle;
        }

        return this.class.staticFieldsData.add(this.offset);
    }

    /** Sets the value of this field. Thread static or literal values cannot be altered yet. */
    set value(value: Il2Cpp.Field.Type) {
        if (this.isThreadStatic || this.isLiteral) {
            warn(`${this.class.type.name}.${this.name} is a thread static or literal field, its value won't be modified.`);
            return;
        }
        write(this.valueHandle, value, this.type);
    }

    /** @internal */
    @shouldBeInstance(true)
    withHolder(instance: Il2Cpp.Object | Il2Cpp.ValueType): Il2Cpp.Field {
        let valueHandle = instance.handle.add(this.offset);
        if (instance instanceof Il2Cpp.ValueType) {
            valueHandle = valueHandle.sub(Il2Cpp.Object.headerSize);
        }

        return overridePropertyValue(new Il2Cpp.Field(this.handle), "valueHandle", valueHandle);
    }

    override toString(): string {
        return (
            (this.isStatic ? "static " : "") +
            this.type.name +
            " " +
            this.name +
            (this.isLiteral
                ? " = " + (this.type.class.isEnum ? this.valueHandle.readS32() : this.value) + ";"
                : "; // 0x" + this.offset.toString(16))
        );
    }
}

Il2Cpp.Field = Il2CppField;

declare global {
    namespace Il2Cpp {
        class Field extends Il2CppField {}
        namespace Field {
            type Type =
                | boolean
                | number
                | Int64
                | UInt64
                | NativePointer
                | Il2Cpp.Pointer
                | Il2Cpp.ValueType
                | Il2Cpp.Object
                | Il2Cpp.String
                | Il2Cpp.Array;
        }
    }
}
