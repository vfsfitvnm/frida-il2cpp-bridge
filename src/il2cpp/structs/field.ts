import { cache } from "decorator-cache-getter";

import { raise } from "../../utils/console";

import { Api } from "../api";
import { nonNullHandle, shouldBeInstance } from "../decorators";
import { Valuable } from "../interfaces";
import { NativeStruct } from "../native-struct";
import { AllowedType } from "../types";
import { readFieldValue, writeFieldValue } from "../utils";

import { _Il2CppClass } from "./class";
import { _Il2CppType } from "./type";

/**
 * Represents a `FieldInfo`.
 */
@nonNullHandle
export class _Il2CppField extends NativeStruct implements Valuable {
    /**
     * @return The class it belongs to.
     */
    @cache
    get class(): _Il2CppClass {
        return new _Il2CppClass(Api._fieldGetClass(this.handle));
    }

    /**
     * @return `true` if it's a instance field, `false` otherwise.
     */
    @cache
    get isInstance(): boolean {
        return Api._fieldIsInstance(this.handle);
    }

    /**
     * @return `true` if it's literal field, `false` otherwise.
     */
    @cache
    get isLiteral(): boolean {
        return Api._fieldIsLiteral(this.handle);
    }

    /**
     * @return `true` if it's a thread  field, `false` otherwise.
     */
    @cache
    get isThreadStatic(): boolean {
        return this.offset == -1;
    }

    /**
     * @return Its name.
     */
    @cache
    get name(): string {
        return Api._fieldGetName(this.handle)!;
    }

    /**
     * A static field offsets is meant as the offset between it's class
     * {@link _Il2CppClass.staticFieldsData} and its location.
     * A static field offsets is meant as the offset between it's object
     * {@link Object.handle | handle} and its location.
     * @return Its offset.
     */
    @cache
    get offset(): number {
        return Api._fieldGetOffset(this.handle);
    }

    /**
     * @return Its type.
     */
    @cache
    get type(): _Il2CppType {
        return new _Il2CppType(Api._fieldGetType(this.handle));
    }

    /**
     * @return Its value.
     */
    get value(): AllowedType {
        return readFieldValue(this.valueHandle, this.type!);
    }

    /**
     * NOTE: Thread static or literal values cannot be altered yet.
     * @param value Its new value.
     */
    @shouldBeInstance(false)
    set value(value) {
        if (this.isThreadStatic || this.isLiteral) {
            raise(`Cannot edit the thread static or literal field "${this.name}".`);
        }
        writeFieldValue(this.valueHandle, value, this.type!);
    }

    /**
     * @return The actual location of its value.
     */
    @shouldBeInstance(false)
    get valueHandle(): NativePointer {
        let handle: NativePointer;
        if (this.isThreadStatic || this.isLiteral) {
            handle = Memory.alloc(Process.pointerSize);
            Api._fieldGetStaticValue(this.handle, handle);
        } else {
            handle = this.class.staticFieldsData.add(this.offset);
        }
        return handle;
    }

    @shouldBeInstance(true)
    asHeld(handle: NativePointer): Valuable {
        const type = this.type;
        return {
            valueHandle: handle,
            get value(): AllowedType {
                return readFieldValue(handle, type);
            },
            set value(value: AllowedType) {
                writeFieldValue(handle, value, type);
            }
        } as Valuable;
    }
}
